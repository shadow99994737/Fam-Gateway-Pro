# Aapki site ka address (bina domain ke, localhost use karo)
PUBLIC_URL=http://localhost:8000

SECRET_KEY=sk_live_9f8a7b6c5d4e3f2a1b0c7e6d5c4b3a2
SUPPORT_TELEGRAM=@NXCDORAEMON
# Proxy ke peeche chal rahe ho to 1
TRUST_PROXY=1
# FamPay ke mail domains
SENDER_DOMAINS=famapp.in,fampay.in,famapp.com,fampay.com
# Strict authentication on
STRICT_AUTH=1
# Kitne din peeche tak mail dhoondhna
LOOKBACK_DAYS=2 
# Premium plan zaroori hai (code me hamesha ON)
REQUIRE_SUBSCRIPTION=1

# ---- FamGateway (famgateway.in) - Plans / Admin Panel ke payments isi se auto-verify hote hain ----
# Admin Panel > Settings se bhi change kar sakte ho (wahan priority zyada hai).
FAMGATEWAY_API_KEY=fam_830991e03a863f4d7607d384fae0295e
# Plan payments apni FamApp Railway API (/api.php) se verify hote hain
FAMGATEWAY_BASE_URL=https://famapp-production-daca.up.railway.app
