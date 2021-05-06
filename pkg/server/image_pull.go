/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"
	containerdimages "github.com/containerd/containerd/images"
	"github.com/containerd/containerd/labels"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/reference"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/containerd/containerd/snapshots"
	distribution "github.com/docker/distribution/reference"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

// For image management:
// 1) We have an in-memory metadata index to:
//   a. Maintain ImageID -> RepoTags, ImageID -> RepoDigset relationships; ImageID
//   is the digest of image config, which conforms to oci image spec.
//   b. Cache constant and useful information such as image chainID, config etc.
//   c. An image will be added into the in-memory metadata only when it's successfully
//   pulled and unpacked.
//
// 2) We use containerd image metadata store and content store:
//   a. To resolve image reference (digest/tag) locally. During pulling image, we
//   normalize the image reference provided by user, and put it into image metadata
//   store with resolved descriptor. For the other operations, if image id is provided,
//   we'll access the in-memory metadata index directly; if image reference is
//   provided, we'll normalize it, resolve it in containerd image metadata store
//   to get the image id.
//   b. As the backup of in-memory metadata in 1). During startup, the in-memory
//   metadata could be re-constructed from image metadata store + content store.
//
// Several problems with current approach:
// 1) An entry in containerd image metadata store doesn't mean a "READY" (successfully
// pulled and unpacked) image. E.g. during pulling, the client gets killed. In that case,
// if we saw an image without snapshots or with in-complete contents during startup,
// should we re-pull the image? Or should we remove the entry?
//
// yanxuean: We can't delete image directly, because we don't know if the image
// is pulled by us. There are resource leakage.
//
// 2) Containerd suggests user to add entry before pulling the image. However if
// an error occurs during the pulling, should we remove the entry from metadata
// store? Or should we leave it there until next startup (resource leakage)?
//
// 3) The cri plugin only exposes "READY" (successfully pulled and unpacked) images
// to the user, which are maintained in the in-memory metadata index. However, it's
// still possible that someone else removes the content or snapshot by-pass the cri plugin,
// how do we detect that and update the in-memory metadata correspondingly? Always
// check whether corresponding snapshot is ready when reporting image status?
//
// 4) Is the content important if we cached necessary information in-memory
// after we pull the image? How to manage the disk usage of contents? If some
// contents are missing but snapshots are ready, is the image still "READY"?

// PullImage pulls an image with authentication config.
func (c *criService) PullImage(ctx context.Context, r *runtime.PullImageRequest) (*runtime.PullImageResponse, error) {
	imageRef := r.GetImage().GetImage()
	namedRef, err := distribution.ParseDockerRef(imageRef)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse image reference %q", imageRef)
	}
	ref := namedRef.String()
	if ref != imageRef {
		log.G(ctx).Debugf("PullImage using normalized image ref: %q", ref)
	}
	resolver, _, err := c.getResolver(ctx, ref, c.credentials(r.GetAuth()))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to resolve image %q", ref)
	}

	var (
		isSchema1    bool
		imageHandler containerdimages.HandlerFunc = func(_ context.Context,
			desc imagespec.Descriptor) ([]imagespec.Descriptor, error) {
			if desc.MediaType == containerdimages.MediaTypeDockerSchema1Manifest {
				isSchema1 = true
			}
			return nil, nil
		}
	)

	pullOpts := []containerd.RemoteOpt{
		containerd.WithSchema1Conversion,
		containerd.WithResolver(resolver),
		containerd.WithPullSnapshotter(c.getDefaultSnapshotterForSandbox(r.GetSandboxConfig())),
		containerd.WithPullUnpack,
		containerd.WithPullLabel(imageLabelKey, imageLabelValue),
		containerd.WithImageHandler(imageHandler),
		containerd.WithPullLabels(snapshots.FilterInheritedLabels(r.GetSandboxConfig().GetAnnotations())),
	}

	if !c.config.ContainerdConfig.DisableSnapshotAnnotations {
		pullOpts = append(pullOpts,
			containerd.WithImageHandlerWrapper(appendInfoHandlerWrapper(ref)))
	}

	image, err := c.client.Pull(ctx, ref, pullOpts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to pull and unpack image %q", ref)
	}

	configDesc, err := image.Config(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "get image config descriptor")
	}
	imageID := configDesc.Digest.String()

	repoDigest, repoTag := getRepoDigestAndTag(namedRef, image.Target().Digest, isSchema1)
	for _, r := range []string{imageID, repoTag, repoDigest} {
		if r == "" {
			continue
		}
		if err := c.createImageReference(ctx, r, image.Target()); err != nil {
			return nil, errors.Wrapf(err, "failed to create image reference %q", r)
		}
		// Update image store to reflect the newest state in containerd.
		// No need to use `updateImage`, because the image reference must
		// have been managed by the cri plugin.
		if err := c.imageStore.Update(ctx, r); err != nil {
			return nil, errors.Wrapf(err, "failed to update image store %q", r)
		}
	}

	log.G(ctx).Debugf("Pulled image %q with image id %q, repo tag %q, repo digest %q", imageRef, imageID,
		repoTag, repoDigest)
	// NOTE(random-liu): the actual state in containerd is the source of truth, even we maintain
	// in-memory image store, it's only for in-memory indexing. The image could be removed
	// by someone else anytime, before/during/after we create the metadata. We should always
	// check the actual state in containerd before using the image or returning status of the
	// image.
	return &runtime.PullImageResponse{ImageRef: imageID}, nil
}

// ParseAuth parses AuthConfig and returns username and password/secret required by containerd.
func ParseAuth(auth *runtime.AuthConfig) (string, string, error) {
	if auth == nil {
		return "", "", nil
	}
	if auth.Username != "" {
		return auth.Username, auth.Password, nil
	}
	if auth.IdentityToken != "" {
		return "", auth.IdentityToken, nil
	}
	if auth.Auth != "" {
		decLen := base64.StdEncoding.DecodedLen(len(auth.Auth))
		decoded := make([]byte, decLen)
		_, err := base64.StdEncoding.Decode(decoded, []byte(auth.Auth))
		if err != nil {
			return "", "", err
		}
		fields := strings.SplitN(string(decoded), ":", 2)
		if len(fields) != 2 {
			return "", "", errors.Errorf("invalid decoded auth: %q", decoded)
		}
		user, passwd := fields[0], fields[1]
		return user, strings.Trim(passwd, "\x00"), nil
	}
	// TODO(random-liu): Support RegistryToken.
	return "", "", errors.New("invalid auth config")
}

// createImageReference creates image reference inside containerd image store.
// Note that because create and update are not finished in one transaction, there could be race. E.g.
// the image reference is deleted by someone else after create returns already exists, but before update
// happens.
func (c *criService) createImageReference(ctx context.Context, name string, desc imagespec.Descriptor) error {
	img := containerdimages.Image{
		Name:   name,
		Target: desc,
		// Add a label to indicate that the image is managed by the cri plugin.
		Labels: map[string]string{imageLabelKey: imageLabelValue},
	}
	// TODO(random-liu): Figure out which is the more performant sequence create then update or
	// update then create.
	oldImg, err := c.client.ImageService().Create(ctx, img)
	if err == nil || !errdefs.IsAlreadyExists(err) {
		return err
	}
	if oldImg.Target.Digest == img.Target.Digest && oldImg.Labels[imageLabelKey] == imageLabelValue {
		return nil
	}
	_, err = c.client.ImageService().Update(ctx, img, "target", "labels")
	return err
}

// updateImage updates image store to reflect the newest state of an image reference
// in containerd. If the reference is not managed by the cri plugin, the function also
// generates necessary metadata for the image and make it managed.
func (c *criService) updateImage(ctx context.Context, r string) error {
	img, err := c.client.GetImage(ctx, r)
	if err != nil && !errdefs.IsNotFound(err) {
		return errors.Wrap(err, "get image by reference")
	}
	if err == nil && img.Labels()[imageLabelKey] != imageLabelValue {
		// Make sure the image has the image id as its unique
		// identifier that references the image in its lifetime.
		configDesc, err := img.Config(ctx)
		if err != nil {
			return errors.Wrap(err, "get image id")
		}
		id := configDesc.Digest.String()
		if err := c.createImageReference(ctx, id, img.Target()); err != nil {
			return errors.Wrapf(err, "create image id reference %q", id)
		}
		if err := c.imageStore.Update(ctx, id); err != nil {
			return errors.Wrapf(err, "update image store for %q", id)
		}
		// The image id is ready, add the label to mark the image as managed.
		if err := c.createImageReference(ctx, r, img.Target()); err != nil {
			return errors.Wrap(err, "create managed label")
		}
	}
	// If the image is not found, we should continue updating the cache,
	// so that the image can be removed from the cache.
	if err := c.imageStore.Update(ctx, r); err != nil {
		return errors.Wrapf(err, "update image store for %q", r)
	}
	return nil
}

// credentials returns a credential function for docker resolver to use.
func (c *criService) credentials(auth *runtime.AuthConfig) func(string) (string, string, error) {
	return func(host string) (string, string, error) {
		if auth == nil {
			// Get default auth from config.
			for h, ac := range c.config.Registry.Auths {
				u, err := url.Parse(h)
				if err != nil {
					return "", "", errors.Wrapf(err, "parse auth host %q", h)
				}
				if u.Host == host {
					auth = toRuntimeAuthConfig(ac)
					break
				}
			}
		}
		return ParseAuth(auth)
	}
}

// getResolver tries registry mirrors and the default registry, and returns the resolver and descriptor
// from the first working registry.
func (c *criService) getResolver(ctx context.Context, ref string, cred func(string) (string, string, error)) (remotes.Resolver, imagespec.Descriptor, error) {
	refspec, err := reference.Parse(ref)
	if err != nil {
		return nil, imagespec.Descriptor{}, errors.Wrap(err, "parse image reference")
	}
	// Try mirrors in order first, and then try default host name.
	for _, e := range c.config.Registry.Mirrors[refspec.Hostname()].Endpoints {
		u, err := url.Parse(e)
		if err != nil {
			return nil, imagespec.Descriptor{}, errors.Wrapf(err, "parse registry endpoint %q", e)
		}
		resolver := docker.NewResolver(docker.ResolverOptions{
			Authorizer: docker.NewAuthorizer(http.DefaultClient, cred),
			Client:     http.DefaultClient,
			Host:       func(string) (string, error) { return u.Host, nil },
			// By default use "https".
			PlainHTTP: u.Scheme == "http",
		})
		_, desc, err := resolver.Resolve(ctx, ref)
		if err == nil {
			return resolver, desc, nil
		}
		// Continue to try next endpoint
	}
	client := &http.Client{
		CheckRedirect: checkRedirecter(ctx),
	}
	resolver := docker.NewResolver(docker.ResolverOptions{
		Credentials: cred,
		Client:      client,
	})
	_, desc, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return nil, imagespec.Descriptor{}, errors.Wrap(err, "no available registry endpoint")
	}
	return resolver, desc, nil
}

// TODO: JTERRY75 set these by using the containerd/containerd/remotes/docker
// resolver and add an opt to set the ClientRedirect.
func checkRedirecter(ctx context.Context) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		log.G(ctx).WithFields(requestFields(req)).Debug("do request redirect")
		for i, v := range via {
			log.G(ctx).WithFields(requestFields(v)).Debugf("do request redirect via %d", i)
		}
		return nil
	}
}

func requestFields(req *http.Request) logrus.Fields {
	fields := map[string]interface{}{
		"request.method": req.Method,
	}
	if req.URL != nil {
		fields["url"] = req.URL.String()
	}
	for k, vals := range req.Header {
		k = strings.ToLower(k)
		if k == "authorization" {
			continue
		}
		for i, v := range vals {
			field := "request.header." + k
			if i > 0 {
				field = fmt.Sprintf("%s.%d", field, i)
			}
			fields[field] = v
		}
	}

	return logrus.Fields(fields)
}

const (
	// targetRefLabel is a label which contains image reference and will be passed
	// to snapshotters.
	targetRefLabel = "containerd.io/snapshot/cri.image-ref"
	// targetManifestDigestLabel is a label which contains manifest digest and will be passed
	// to snapshotters.
	targetManifestDigestLabel = "containerd.io/snapshot/cri.manifest-digest"
	// targetLayerDigestLabel is a label which contains layer digest and will be passed
	// to snapshotters.
	targetLayerDigestLabel = "containerd.io/snapshot/cri.layer-digest"
	// targetImageLayersLabel is a label which contains layer digests contained in
	// the target image and will be passed to snapshotters for preparing layers in
	// parallel. Skipping some layers is allowed and only affects performance.
	targetImageLayersLabel = "containerd.io/snapshot/cri.image-layers"
)

// appendInfoHandlerWrapper makes a handler which appends some basic information
// of images like digests for manifest and their child layers as annotations during unpack.
// These annotations will be passed to snapshotters as labels. These labels will be
// used mainly by stargz-based snapshotters for querying image contents from the
// registry.
func appendInfoHandlerWrapper(ref string) func(f containerdimages.Handler) containerdimages.Handler {
	return func(f containerdimages.Handler) containerdimages.Handler {
		return containerdimages.HandlerFunc(func(ctx context.Context, desc imagespec.Descriptor) ([]imagespec.Descriptor, error) {
			children, err := f.Handle(ctx, desc)
			if err != nil {
				return nil, err
			}
			switch desc.MediaType {
			case imagespec.MediaTypeImageManifest, containerdimages.MediaTypeDockerSchema2Manifest:
				for i := range children {
					c := &children[i]
					if containerdimages.IsLayerType(c.MediaType) {
						if c.Annotations == nil {
							c.Annotations = make(map[string]string)
						}
						c.Annotations[targetRefLabel] = ref
						c.Annotations[targetLayerDigestLabel] = c.Digest.String()
						c.Annotations[targetImageLayersLabel] = getLayers(ctx, targetImageLayersLabel, children[i:], labels.Validate)
						c.Annotations[targetManifestDigestLabel] = desc.Digest.String()
					}
				}
			}
			return children, nil
		})
	}
}

// getLayers returns comma-separated digests based on the passed list of
// descriptors. The returned list contains as many digests as possible as well
// as meets the label validation.
func getLayers(ctx context.Context, key string, descs []imagespec.Descriptor, validate func(k, v string) error) (layers string) {
	var item string
	for _, l := range descs {
		if containerdimages.IsLayerType(l.MediaType) {
			item = l.Digest.String()
			if layers != "" {
				item = "," + item
			}
			// This avoids the label hits the size limitation.
			if err := validate(key, layers+item); err != nil {
				log.G(ctx).WithError(err).WithField("label", key).Debugf("%q is omitted in the layers list", l.Digest.String())
				break
			}
			layers += item
		}
	}
	return
}
