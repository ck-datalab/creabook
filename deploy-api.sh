#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Déploiement MANUEL Créa'Book API → Scaleway
# (le déploiement automatique se fait via .github/workflows/deploy.yml)
#
# Usage : bash deploy-api.sh <scw-secret-key>
# Ex    : bash deploy-api.sh 7e1b9caf-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# ─────────────────────────────────────────────────────────────────────────────
set -e

SCW_KEY=${1:?'Argument manquant : Scaleway Secret Key'}

# Emails juridiques — à définir dans l'environnement avant d'appeler ce script :
#   export RESEND_JURIDIQUE_CECCA=lior.feiguelman@cecca.fr
#   export RESEND_JURIDIQUE_ETOILE=ornella.khalfa@cecca.fr
: "${RESEND_JURIDIQUE_CECCA:?'Variable RESEND_JURIDIQUE_CECCA non définie'}"
: "${RESEND_JURIDIQUE_ETOILE:?'Variable RESEND_JURIDIQUE_ETOILE non définie'}"

REGION="nl-ams"
NAMESPACE="creabook"
CONTAINER_ID="0f2dfe3a-ef05-458e-9f7d-887d62799362"
IMAGE="rg.${REGION}.scw.cloud/${NAMESPACE}/creabook-api"

echo "→ Login Scaleway Registry..."
echo "$SCW_KEY" | docker login "rg.${REGION}.scw.cloud" -u nologin --password-stdin

echo "→ Build image (linux/amd64)..."
DOCKER_HOST=unix:///Users/macbook/.docker/run/docker.sock \
  docker build --platform linux/amd64 -f api/Dockerfile -t "${IMAGE}:latest" .

echo "→ Push image..."
DOCKER_HOST=unix:///Users/macbook/.docker/run/docker.sock \
  docker push "${IMAGE}:latest"

echo "→ Redéploiement du container Scaleway..."
scw container container update "${CONTAINER_ID}" \
  region="${REGION}" \
  "environment-variables.RESEND_JURIDIQUE_CECCA=lior.feiguelman@cecca.fr" \
  "environment-variables.RESEND_JURIDIQUE_ETOILE=ornella.khalfa@cecca.fr"

scw container container deploy "${CONTAINER_ID}" region="${REGION}"

echo ""
echo "✅ Déployé : ${IMAGE}:latest"
echo "   → https://creabookf74b3ee3-creabook.functions.fnc.nl-ams.scw.cloud"
echo ""
echo "⚠️  Secrets Scaleway (HUBSPOT_TOKEN, TOKEN_SECRET, RESEND_API_KEY)"
echo "    sont déjà sur le container — ils ne sont pas modifiés par ce script."
