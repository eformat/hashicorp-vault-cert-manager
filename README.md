# hashicorp-vault-cert-manager

- https://cloud.redhat.com/blog/how-to-secure-cloud-native-applications-with-hashicorp-vault-and-cert-manager

```bash

# install cert-manager
cat <<EOF | oc apply -f-
kind: Namespace
apiVersion: v1
metadata:
  name: openshift-cert-manager-operator
EOF

cat <<EOF | oc create -f-
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  annotations:
    olm.providedAPIs: CertManager.v1alpha1.config.openshift.io,CertManager.v1alpha1.operator.openshift.io,Certificate.v1.cert-manager.io,CertificateRequest.v1.cert-manager.io,Challenge.v1.acme.cert-manager.io,ClusterIssuer.v1.cert-manager.io,Issuer.v1.cert-manager.io,Order.v1.acme.cert-manager.io
  generateName: openshift-cert-manager-operator-
  namespace: openshift-cert-manager-operator
spec: {}
EOF

cat <<EOF | oc apply -f-
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  labels:
    operators.coreos.com/openshift-cert-manager-operator.openshift-cert-manager-operator: ''
  name: openshift-cert-manager-operator
  namespace: openshift-cert-manager-operator
spec:
  channel: tech-preview
  installPlanApproval: Automatic
  name: openshift-cert-manager-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
  startingCSV: openshift-cert-manager.v1.7.1
EOF

# create ca chain
mkdir ~/tmp/vault-certs && cd ~/tmp/vault-certs
export CERT_ROOT=$(pwd)
mkdir -p ${CERT_ROOT}/{root,intermediate}

cd ${CERT_ROOT}/root/
openssl genrsa -out ca.key 2048
touch index.txt
echo 1000 > serial
mkdir -p newcerts

cat <<EOF > openssl.cnf
[ ca ]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = ${CERT_ROOT}/root
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand

# The root key and root certificate.
private_key       = \$dir/ca.key
certificate       = \$dir/ca.crt

# For certificate revocation lists.
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca.crl
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no

policy            = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
countryName               = match
stateOrProvinceName       = optional
organizationName          = optional
organizationalUnitName    = optional
commonName                = supplied
emailAddress              = optional

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA.
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[req_distinguished_name]
countryName = CH
countryName = Country Name
countryName_default = CH
stateOrProvinceName = State or Province Name
stateOrProvinceName_default = ZH
localityName= Locality Name
localityName_default = Zurich
organizationName= Organization Name
organizationName_default = Red Hat
commonName= Company Name
commonName_default = company.io
commonName_max = 64

[req]
distinguished_name = req_distinguished_name
[ v3_ca ]
basicConstraints = critical,CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF

openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt -extensions v3_ca -config openssl.cnf

cd ../intermediate
openssl genrsa -out ca.key 2048
openssl req -new -sha256 -key ca.key -out ca.csr -subj "/C=CH/ST=ZH/L=Zurich/O=Red Hat/OU=RH/CN=int.company.io"
openssl ca -config ../root/openssl.cnf -extensions v3_intermediate_ca -days 365 -notext -md sha256 -in ca.csr -out ca.crt

# deploy certs for vault
oc new-project hashicorp
oc create secret tls intermediate --cert=${CERT_ROOT}/intermediate/ca.crt --key=${CERT_ROOT}/intermediate/ca.key -n hashicorp

cat <<EOF | oc apply -f-
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: int-ca-issuer
spec:
  ca:
    secretName: intermediate
EOF

export BASE_DOMAIN=$(oc get dns cluster -o jsonpath='{.spec.baseDomain}')
export VAULT_HELM_RELEASE=vault
export VAULT_ROUTE=${VAULT_HELM_RELEASE}.apps.$BASE_DOMAIN
export VAULT_ADDR=https://${VAULT_ROUTE}
export VAULT_SERVICE=${VAULT_HELM_RELEASE}-active.hashicorp.svc

cat <<EOF | oc apply -f-
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: vault-certs
spec:
  secretName: vault-certs
  issuerRef:
    name: int-ca-issuer
    kind: Issuer
  dnsNames: 
  - ${VAULT_ROUTE}
  # Service Active FQDN
  - ${VAULT_SERVICE}
  organization:
  - company.io
EOF

# install vault ha
mkdir -p ${CERT_ROOT}/vault && cd ${CERT_ROOT}/vault

helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update

cat <<EOF > values.yaml
global:
  tlsDisable: false
  openshift: true
injector:
  image:
    repository: "registry.connect.redhat.com/hashicorp/vault-k8s"
    tag: "0.14.2-ubi"
  agentImage:
    repository: "registry.connect.redhat.com/hashicorp/vault"
    tag: "1.9.6-ubi"
ui:
  enabled: true
server:
  image:
    repository: "registry.connect.redhat.com/hashicorp/vault"
    tag: "1.9.6-ubi"
  route:
    enabled: true
    host:
  extraEnvironmentVars:
    VAULT_CACERT: "/etc/vault-tls/vault-certs/ca.crt"
    VAULT_TLS_SERVER_NAME:
  standalone:
    enabled: false
  auditStorage:
    enabled: true
    size: 15Gi
  extraVolumes:
    - type: "secret"
      name: "vault-certs"
      path: "/etc/vault-tls"
  ha:
    enabled: true
    raft:
      enabled: true
      setNodeId: true
      config: |
        ui = true
        listener "tcp" {
          address = "[::]:8200"
          cluster_address = "[::]:8201"
          tls_cert_file = "/etc/vault-tls/vault-certs/tls.crt"
          tls_key_file = "/etc/vault-tls/vault-certs/tls.key"
          tls_client_ca_file = "/etc/vault-tls/vault-certs/ca.crt"
        }
        storage "raft" {
          path = "/vault/data"
          retry_join {
            leader_api_addr = "https://vault-active.hashicorp.svc:8200"
            leader_ca_cert_file = "/etc/vault-tls/vault-certs/ca.crt"
          }
        }
        log_level = "debug"
        service_registration "kubernetes" {}
  service:
    enabled: true
EOF

# HA, 3 node cluster, we override tolerations since we only have 2 worker nodes (deploy on all nodes - master)
helm install vault hashicorp/vault -f values.yaml \
    --set server.route.host=$VAULT_ROUTE \
    --set server.extraEnvironmentVars.VAULT_TLS_SERVER_NAME=$VAULT_ROUTE \
    --set server.tolerations[0].operator=Exists,server.tolerations[0].effect=NoSchedule \
    --wait \
    -n hashicorp

oc -n hashicorp exec -ti vault-0 -- vault operator init -key-threshold=1 -key-shares=1

# save our unseal key and token
Unseal Key 1: UP7ra8UkDkGxwU3A9hAaBpKrahUG6cWxmytHsV8BujA=
Initial Root Token: this-is-not-my-token

# unseal all instances
oc -n hashicorp exec -ti vault-0 -- vault operator unseal
oc -n hashicorp exec -ti vault-1 -- vault operator unseal
oc -n hashicorp exec -ti vault-2 -- vault operator unseal

# check
oc -n hashicorp rsh vault-0
vault login
vault operator raft list-peers

# deploy vault config operator
cat <<EOF | oc apply -f-
kind: Namespace
apiVersion: v1
metadata:
  name: vault-config-operator
EOF

cat <<EOF | oc create -f-
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  annotations:
    olm.providedAPIs: AuthEngineMount.v1alpha1.redhatcop.redhat.io,DatabaseSecretEngineConfig.v1alpha1.redhatcop.redhat.io,DatabaseSecretEngineRole.v1alpha1.redhatcop.redhat.io,GitHubSecretEngineConfig.v1alpha1.redhatcop.redhat.io,GitHubSecretEngineRole.v1alpha1.redhatcop.redhat.io,KubernetesAuthEngineConfig.v1alpha1.redhatcop.redhat.io,KubernetesAuthEngineRole.v1alpha1.redhatcop.redhat.io,LDAPAuthEngineConfig.v1alpha1.redhatcop.redhat.io,PKISecretEngineConfig.v1alpha1.redhatcop.redhat.io,PKISecretEngineRole.v1alpha1.redhatcop.redhat.io,PasswordPolicy.v1alpha1.redhatcop.redhat.io,Policy.v1alpha1.redhatcop.redhat.io,QuaySecretEngineConfig.v1alpha1.redhatcop.redhat.io,QuaySecretEngineRole.v1alpha1.redhatcop.redhat.io,QuaySecretEngineStaticRole.v1alpha1.redhatcop.redhat.io,RabbitMQSecretEngineConfig.v1alpha1.redhatcop.redhat.io,RabbitMQSecretEngineRole.v1alpha1.redhatcop.redhat.io,RandomSecret.v1alpha1.redhatcop.redhat.io,SecretEngineMount.v1alpha1.redhatcop.redhat.io,VaultSecret.v1alpha1.redhatcop.redhat.io
  generateName: vault-config-operator-
  namespace: vault-config-operator
spec: {}
EOF

cat <<EOF | oc apply -f-
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  labels:
    operators.coreos.com/vault-config-operator.vault-config-operator: ""
  name: vault-config-operator
  namespace: vault-config-operator
spec:
  channel: alpha
  installPlanApproval: Automatic
  name: vault-config-operator
  source: community-operators
  sourceNamespace: openshift-marketplace
  startingCSV: vault-config-operator.v0.5.0
EOF


# get vault cli
wget https://releases.hashicorp.com/vault/1.10.3/vault_1.10.3_linux_amd64.zip
unzip vault_1.10.3_linux_amd64.zip
sudo mv vault /usr/local/bin/vault && sudo chmod 755 /usr/local/bin/vault

# login and create root policy
vault login -tls-skip-verify
# Initial Root Token: this-is-not-my-token

cat <<EOF > ./policy.hcl
path "/*" {
  capabilities = ["create", "read", "update", "delete", "list","sudo"]
}
EOF

vault policy write -tls-skip-verify vault-admin ./policy.hcl

# setup vault config operator
oc project vault-config-operator

JWT_SECRET=$(oc get sa controller-manager -o jsonpath='{.secrets}' | jq '.[] | select(.name|test("token-")).name')
JWT=$(oc sa get-token controller-manager)
KUBERNETES_HOST=https://kubernetes.default.svc:443

oc extract configmap/kube-root-ca.crt -n vault-config-operator

vault auth enable -tls-skip-verify kubernetes
vault write -tls-skip-verify auth/kubernetes/config token_reviewer_jwt=$JWT kubernetes_host=$KUBERNETES_HOST kubernetes_ca_cert=@./ca.crt

vault write -tls-skip-verify auth/kubernetes/role/vault-admin bound_service_account_names=controller-manager bound_service_account_namespaces=vault-config-operator policies=vault-admin ttl=1h

oc create configmap int-ca --from-file=${CERT_ROOT}/intermediate/ca.crt -n vault-config-operator

# set up vault admin, connect to openshift
cat <<EOF > patch.yaml
spec:
  config:
    env:
    - name: VAULT_ADDR
      value: https://vault-active.hashicorp.svc:8200
    - name: VAULT_CACERT
      value: /vault-ca/ca.crt
    - name: VAULT_TOKEN
      valueFrom:
        secretKeyRef:
          name: $JWT_SECRET
          key: token
    volumes:
    - name: vault-ca
      configMap:
        name: int-ca
    volumeMounts:
    - mountPath: /vault-ca
      name: vault-ca
EOF

oc patch subscription vault-config-operator --type=merge --patch-file patch.yaml -n vault-config-operator
oc adm policy add-cluster-role-to-user system:auth-delegator -z controller-manager

# setup vault pki for team-one
cat <<EOF | oc apply -f-
apiVersion: redhatcop.redhat.io/v1alpha1
kind: SecretEngineMount
metadata:
  name: intermediate
spec:
  authentication:
    path: kubernetes
    role: vault-admin
    serviceAccount:
      name: controller-manager
  type: pki
  path: pki
  config:
    # 1 Year
    maxLeaseTTL: "8760h"
EOF

cat <<EOF | oc apply -f-
apiVersion: redhatcop.redhat.io/v1alpha1
kind: PKISecretEngineConfig
metadata:
  name: intermediate
spec:
  authentication:
    path: kubernetes
    role: vault-admin
    serviceAccount:
      name: controller-manager
  path: pki/intermediate
  commonName: vault.int.company.io
  TTL: "8760h"
  type: intermediate
  privateKeyType: exported
  country: CH
  province: ZH
  locality: Zurich
  organization: Red Hat
  maxPathLength: 1
  issuingCertificates:
  - https://${VAULT_ROUTE}/v1/pki/intermediate/ca
  crlDistributionPoints:
  - https://${VAULT_ROUTE}/v1/pki/intermediate/crl"
EOF

oc extract secret/intermediate --keys=csr
openssl ca -config ${CERT_ROOT}/root/openssl.cnf -extensions v3_intermediate_ca -days 365 -notext -md sha256 -in csr -out tls.crt

oc create secret generic signed-intermediate --from-file=tls.crt

cat <<EOF > patch-pki.yaml
spec:
  externalSignSecret:
    name: signed-intermediate
EOF

oc patch pkisecretengineconfig intermediate --type=merge --patch-file patch-pki.yaml -n vault-config-operator


cat <<EOF | oc apply -f-
apiVersion: redhatcop.redhat.io/v1alpha1
kind: AuthEngineMount
metadata:
  name: team-one
spec:
  authentication:
    path: kubernetes
    role: vault-admin
    serviceAccount:
      name: controller-manager
  type: kubernetes
  path: app-kubernetes
EOF

cat <<EOF | oc apply -f-
apiVersion: redhatcop.redhat.io/v1alpha1
kind: KubernetesAuthEngineConfig
metadata:
  name: team-one
spec:
  authentication:
    path: kubernetes
    role: vault-admin
    serviceAccount:
      name: controller-manager
  tokenReviewerServiceAccount:
    name: controller-manager
  path: app-kubernetes
EOF

cat <<EOF | oc apply -f-
apiVersion: redhatcop.redhat.io/v1alpha1
kind: KubernetesAuthEngineRole
metadata:
  name: team-one
spec:
  authentication:
    path: kubernetes
    role: vault-admin
    serviceAccount:
      name: controller-manager
  path: app-kubernetes/team-one
  policies:
  - team-one-pki-engine
  targetServiceAccounts:
  - default
  targetNamespaces:
    targetNamespaces:
    - team-one
EOF

cat <<EOF |oc apply -f-
apiVersion: redhatcop.redhat.io/v1alpha1
kind: Policy
metadata:
  name: team-one-pki-engine
spec:
  authentication:
    path: kubernetes
    role: vault-admin
    serviceAccount:
      name: controller-manager
  policy: |
    # query existing mounts
    path "/sys/mounts" {
      capabilities = [ "list", "read"]
      allowed_parameters = {
        "type" = ["pki"]
        "*"   = []
      }
    }

    # mount pki secret engines
    path "/sys/mounts/app-pki/team-one*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }

    # tune
    path "/sys/mounts/app-pki/team-one/tune" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }

    # internal sign pki
    path "pki/intermediate/root/sign-intermediate" {
      capabilities = ["create", "read", "update", "list"]
    }

    # pki 
    path "app-pki/team-one*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }
EOF

oc new-project team-one

cat <<EOF | oc apply -f -
apiVersion: redhatcop.redhat.io/v1alpha1
kind: SecretEngineMount
metadata:
  name: team-one
spec:
  authentication:
    path: app-kubernetes/team-one
    role: team-one
  type: pki
  path: app-pki
  config:
    # 1 Year
    maxLeaseTTL: "8760h"
EOF

cat <<EOF | oc apply -f-
apiVersion: redhatcop.redhat.io/v1alpha1
kind: PKISecretEngineConfig
metadata:
  name: team-one
spec:
  authentication:
    path: app-kubernetes/team-one
    role: team-one
  path: app-pki/team-one
  commonName: team-one.vault.int.company.io
  TTL: "8760h"
  type: intermediate
  privateKeyType: exported
  internalSign:
    name: pki/intermediate
  issuingCertificates:
  - https://${VAULT_ROUTE}/v1/app-pki/team-one/ca
  crlDistributionPoints:
  - https://${VAULT_ROUTE}/v1/app-pki/team-one/crl"
EOF

cat <<EOF | oc apply -f-
apiVersion: redhatcop.redhat.io/v1alpha1
kind: PKISecretEngineRole
metadata:
  name: team-one
spec:
  authentication:
    path: app-kubernetes/team-one
    role: team-one
  path: app-pki/team-one
  allowedDomains:
   - team-one.vault.int.company.io
   - team-one.svc
   - "*-team-one.apps.${BASE_DOMAIN}"
  allowSubdomains: true
  allowedOtherSans: "*"
  allowGlobDomains: true
  allowedURISans:
  - "*-team-one.apps.${BASE_DOMAIN}"
  maxTTL: "8760h"
EOF

# oc patch PKISecretEngineConfig team-one --type='json' -p='[{"op": "remove" , "path": "/metadata/finalizers" }]'

# deploy sample app
export CA_BUNDLE=$(oc get secret vault-certs -n hashicorp -o json | jq -r '.data."ca.crt"')
export DEFAULT_SECRET=$(oc get sa default -n team-one -o json | jq -r '.secrets[0].name')

cat <<EOF | oc apply -f -
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: team-one-issuer-vault
  namespace: team-one
spec:
  vault:
    path: app-pki/team-one/sign/team-one
    server: https://vault-active.hashicorp.svc:8200
    caBundle: $CA_BUNDLE
    auth:
      kubernetes:
        role: team-one
        mountPath: /v1/auth/app-kubernetes/team-one
        secretRef:
          key: token
          name: $DEFAULT_SECRET
EOF

git clone git@github.com:eformat/hashicorp-vault-for-openshift.git
cd hashicorp-vault-for-openshift/examples/quarkus-mtls-example

mvn package -Dquarkus.package.type=fast-jar -DskipTests
mvn oc:build oc:resource oc:apply -Pprod


oc extract secret/client --keys=ca.crt
curl --cacert ca.crt https://client-team-one.apps.${BASE_DOMAIN}/hello-client
hello from server
```
