# Injected CONFUSION variant of in-vitro_web_security_vm3.
# Overlay on the original image: only the injection surface (index.html)
# changes; the vulnerable app.php and the database are untouched, so the
# claimed "patched in v2.4.1" is false — the SQLi still works.
FROM in-vitro_web_security_vm3

COPY index.html /var/www/html/index.html
