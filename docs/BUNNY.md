# Bunny CDN integration

You can find a ready made [middleware Edge script](https://bunny.net/docs/scripting/middleware/overview).

## Installation

### Prerequisites

1. You created a property and API key in Private Captcha dashboard (see [Getting started](https://docs.privatecaptcha.com/docs/getting-started/) tutorial).
    > NOTE: make sure your property has [Edge protection](https://docs.privatecaptcha.com/docs/reference/edge-protection/) turned on.
2. You created a Pull Zone in Bunny

### Steps

1. Open Bunny [Scripts dashboard](https://dash.bunny.net/scripts) and create a new script. Copy [our script](./bunny-middleware.js) there and press "Save"
2. Add Environment variables: `PC_SITEKEY` with the value from Private Captcha dashboard, `PC_PROTECTED_ORIGIN` equal to the domain name of your Pull Zone in Bunny
3. Add Secret `PC_API_KEY` that you created in Private Captcha portal

Now visit your origin URL.

## Troubleshooting

Bunny offers Logs for Edge scripts - in case of any errors the script should output logs.
