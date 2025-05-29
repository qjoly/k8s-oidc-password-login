# OIDC Password Grant for Kubernetes

> Have you ever dreamed of a simple way to decrease the security of your Kubernetes cluster? Goodbye certificates easy authentication, hello password grant type! 😈

This repository provides a simple OIDC Provider to authenticate users on Kubernetes clusters using the password grant type. It is designed to work with the [oidc-login](https://github.com/int128/kubelogin) plugin.

:warning: This is only a proof of concept and should not be used in production environments. I only created this to learn more about OIDC and Kubernetes authentication. It is not secure and should not be used in production environments. Use only if you live on the edge !

**Roadmap:**
- [x] Create a simple OIDC provider
- [x] Integrate with Kubernetes API Server
- [x] Make it totally unsafe and unusable in production
- [x] Ignore security best practices
- [x] Had fun while doing it

## Set up OIDC authentication for Kubernetes

To set up OIDC authentication on the API-Server, you need to add the following flags to the API server configuration in `/etc/kubernetes/manifests/kube-apiserver.yaml`:

```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    # Other existing flags...
    - --oidc-issuer-url=https://oidc.mocha.thoughtless.eu # Change this to your OIDC provider's URL
    - --oidc-client-id=kubernetes
    - --oidc-username-claim=email
    - --oidc-groups-claim=groups
```

If you are using Talos (which is a good choice to run k8s 😇), you can apply the following patch in the machine config of your controlPlanes :

```yaml
cluster:
  apiServer:
    extraArgs:
      oidc-issuer-url: "https://oidc.mocha.thoughtless.eu" # Change this to your OIDC provider's URL
      oidc-client-id: kubernetes
      oidc-username-claim: email
      oidc-groups-claim: groups
```

Once the API Server is configured, you can create a `ClusterRoleBinding` to bind the `cluster-admin` role to the OIDC user. This will allow the user to perform any action on the cluster.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oidc-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: User
  name: "admin@une-tasse-de.cafe" # Change this to the OIDC user you want to bind.
  apiGroup: rbac.authorization.k8s.io
```

## Configure `oidc-login` plugin
To use the OIDC provider with `kubectl`, you need to install the [oidc-login](https://github.com/int128/kubelogin).

```bash
# Homebrew (macOS and Linux)
brew install kubelogin
# Krew (macOS, Linux, Windows and ARM)
kubectl krew install oidc-login
# Chocolatey (Windows)
choco install kubelogin
```

Once you have installed the `oidc-login` plugin, you can set it up to use the OIDC provider. You can do this by running the following command:

```bash
kubectl oidc-login setup \
  --oidc-issuer-url=https://oidc.mocha.thoughtless.eu \
  --oidc-client-id=kubernetes \
  --grant-type=password --username=admin
```

This will give you all commands you need to set up your `kubeconfig` file to use the OIDC provider. The `oidc-login` plugin will handle the authentication process for you.

[![asciicast](https://asciinema.org/a/ZzL6LSS3cFdsnttRTkCNUCpqo.svg)](https://asciinema.org/a/ZzL6LSS3cFdsnttRTkCNUCpqo)

## Example configuration for `kubectl` with `oidc-login`

To configure `kubectl` to use the OIDC provider, you can create a `kubeconfig` file like the one below. This example uses the `oidc-login` plugin to authenticate with the OIDC provider using the password grant type.

Keep in mind that the `certificate-authority-data` field should contain the base64-encoded CA certificate of your Kubernetes cluster. You can obtain this from your cluster administrator or by extracting it from your existing kubeconfig file.

```yaml
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJpVENDQVRDZ0F3SUJBZ0lSQU5YblJvS3pTS3k3K2R3M28wSzR5N2N3Q2dZSUtvWkl6ajBFQXdJd0ZURVQKTUJFR0ExVUVDaE1LYTNWaVpYSnVaWFJsY3pBZUZ3MHlOVEExTWpneE1qSXdOVE5hRncwek5UQTFNall4TWpJdwpOVE5hTUJVeEV6QVJCZ05WQkFvVENtdDFZbVZ5Ym1WMFpYTXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CCkJ3TkNBQVQ1b3pkSE9MYzhjbHRNdzExejN0elNveUo3S2E4Z3cvbG1Sbnd1Tkp1R3R2MUxvOGV0eEVCSkhuU2EKQ2lHaFo2d2dBUVlpbGxqL0xGY282WCtXZmRwaW8yRXdYekFPQmdOVkhROEJBZjhFQkFNQ0FvUXdIUVlEVlIwbApCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0hRWURWUjBPCkJCWUVGRGx3K0VwT21xM3RWY3FlQ3JhYnBLWnRIQkxYTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUdRa0ovSWkKVjBGRWU0cFRzbmFZSkFRNjVqM3F6SC9mV2xXdWFCM284K0NSQWlBMk1NM2hxTVJvSHk4VWkyT0czUS9hQnQycwpsa3psb2lEQzZlL1ZMTWN0WEE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    server: https://my-cluster-IP:6443
  name: cluster-oidc
contexts:
- context:
    cluster: cluster-oidc
    namespace: default
    user: oidc-real
  name: cluster-oidc
current-context: cluster-oidc
kind: Config
preferences: {}
users:
- name: oidc-real
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      args:
      - oidc-login
      - get-token
      # Change the issuer URL to your OIDC provider's URL
      - --oidc-issuer-url=https://oidc.mocha.thoughtless.eu
      - --oidc-client-id=kubernetes
      - --grant-type=password
      # (Optional) The username to use for the OIDC login.
      # If not specified, the plugin will prompt for it.
      - --username=admin
      command: kubectl
      env: null
      provideClusterInfo: false
```
