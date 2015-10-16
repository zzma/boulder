-- Before setting up any privileges, we revoke existing ones to make sure we
-- start from a clean slate.
-- Note that dropping a non-existing user produces an error that aborts the
-- script, so we first grant a harmless privilege to each user to ensure it
-- exists.
GRANT USAGE ON *.* TO 'policy'@'localhost';
DROP USER 'policy'@'localhost';
GRANT USAGE ON *.* TO 'sa'@'localhost';
DROP USER 'sa'@'localhost';
GRANT USAGE ON *.* TO 'ocsp-responder'@'localhost';
DROP USER 'ocsp-responder'@'localhost';
GRANT USAGE ON *.* TO 'ocsp-updater'@'localhost';
DROP USER 'ocsp-updater'@'localhost';
GRANT USAGE ON *.* TO 'revoker'@'localhost';
DROP USER 'revoker'@'localhost';
GRANT USAGE ON *.* TO 'cert-importer'@'localhost';
DROP USER 'cert-importer'@'localhost';
GRANT USAGE ON *.* TO 'mailer'@'localhost';
DROP USER 'mailer'@'localhost';
GRANT USAGE ON *.* TO 'cert_checker'@'localhost';
DROP USER 'cert_checker'@'localhost';

