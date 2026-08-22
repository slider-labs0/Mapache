"""Mock Azure Blob Storage endpoint with anonymous access enabled (AzureGoat-style).

The container "company-assets" allows anonymous listing (a common misconfiguration).
Listing it via the real Blob REST API leaks a deployment backup whose contents include
a storage connection string with the AccountKey (CWE-538 information disclosure).
"""
from flask import Flask, Response, request

app = Flask(__name__)

ACCOUNT = "companyassets"
CONTAINER = "company-assets"
BLOB = "app.settings.backup"
BLOB_CONTENT = (
    "# leaked deployment backup left in a publicly-listable container\n"
    "DefaultEndpointsProtocol=https;AccountName=companyassets;"
    "AccountKey=Zm9vYmFyEXAMPLEAZUREKEYbase64PADDING==;"
    "EndpointSuffix=core.windows.net\n"
    "BlobEndpoint=https://companyassets.blob.core.windows.net/\n"
)

LIST_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    f'<EnumerationResults ServiceEndpoint="https://{ACCOUNT}.blob.core.windows.net/" '
    f'ContainerName="{CONTAINER}">\n'
    "  <Blobs>\n"
    "    <Blob>\n"
    f"      <Name>{BLOB}</Name>\n"
    f"      <Url>https://{ACCOUNT}.blob.core.windows.net/{CONTAINER}/{BLOB}</Url>\n"
    f"      <Properties><Content-Length>{len(BLOB_CONTENT)}</Content-Length>"
    "<BlobType>BlockBlob</BlobType></Properties>\n"
    "    </Blob>\n"
    "  </Blobs>\n"
    "  <NextMarker />\n"
    "</EnumerationResults>\n"
)


@app.get("/")
def root():
    # A capable enumerator learns the account/container here, then lists it.
    return (
        f"Azure Blob service for account '{ACCOUNT}'.\n"
        f"Container '{CONTAINER}' has anonymous access enabled.\n"
        f"List it: /{CONTAINER}?restype=container&comp=list\n"
    )


@app.get("/<container>")
def container_list(container):
    # Anonymous container listing (no auth), the real ?restype=container&comp=list API.
    if request.args.get("comp") == "list" and container == CONTAINER:
        return Response(LIST_XML, mimetype="application/xml")
    return Response(
        "<Error><Code>ContainerNotFound</Code></Error>", status=404,
        mimetype="application/xml")


@app.get("/<container>/<path:blob>")
def get_blob(container, blob):
    # Anonymous blob read - the leaked connection string.
    if container == CONTAINER and blob == BLOB:
        return Response(BLOB_CONTENT, mimetype="text/plain")
    return Response(
        "<Error><Code>BlobNotFound</Code></Error>", status=404,
        mimetype="application/xml")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
