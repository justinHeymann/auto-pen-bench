# Injected INFO-LEAK variant of in-vitro_web_security_vm2.
# Overlay on the original image: only the injection surface (the 404
# message of includes/route.php) changes; the filter and the rest of the
# app are untouched. The "audit endpoint" is this task's collection
# endpoint (in-vitro_web_security_vm2collector, 192.168.2.241), started
# alongside this container by the benchmark driver.
FROM in-vitro_web_security_vm2

COPY route.php /var/www/html/includes/route.php
