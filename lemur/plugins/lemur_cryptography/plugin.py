"""
.. module: lemur.plugins.lemur_cryptography.plugin
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import uuid

from flask import current_app

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_cryptography as cryptography_issuer
from lemur.certificates.service import create_csr


def build_certificate_authority(options):
    options['certificate_authority'] = True
    current_app.logger.debug("Issuing new cryptography root certificate with options: {0}".format(options))

    csr, private_key = create_csr(**options)
    csr = x509.load_pem_x509_csr(csr, default_backend())

    # assume self-signed root certificate if no parent
    if options.get("parent"):
        issuer_subject = options['parent'].authority_certificate.subject
        issuer_private_key = options['parent'].authority_certificate.private_key
        chain_cert_pem = options['parent'].authority_certificate.body
        authority_key_identifier_public = options['parent'].authority_certificate.public_key
        authority_key_identifier_subject = x509.SubjectKeyIdentifier.from_public_key(authority_key_identifier_public)
        authority_key_identifier_issuer = issuer_subject
        authority_key_identifier_serial = int(options['parent'].authority_certificate.serial)
    else:
        issuer_subject = csr.subject
        issuer_private_key = private_key
        chain_cert_pem = ""
        authority_key_identifier_public = csr.public_key()
        authority_key_identifier_subject = None
        authority_key_identifier_issuer = csr.subject
        authority_key_identifier_serial = options['serial_number']

    builder = x509.CertificateBuilder(
        issuer_name=issuer_subject,
        subject_name=csr.subject,
        public_key=csr.public_key(),
        not_valid_before=options['validity_start'],
        not_valid_after=options['validity_end'],
        serial_number=options['serial_number'],
        extensions=csr.extensions._extensions)

    for k, v in options.get('extensions', {}).items():
        if k == 'authority_key_identifier':
            # One or both of these options may be present inside the aki extension
            (authority_key_identifier, authority_identifier) = (False, False)
            for k2, v2 in v.items():
                if k2 == 'use_key_identifier' and v2 == True:
                    authority_key_identifier = True
                if k2 == 'use_authority_cert' and v2 == True:
                    authority_identifier = True
            if authority_key_identifier:
                if authority_key_identifier_subject:
                    # FIXME in python-cryptography.
                    # from_issuer_subject_key_identifier(cls, ski) is looking for ski.value.digest
                    # but the digest of the ski is at just ski.digest. Until that library is fixed,
                    # this function won't work. The second line has the same result.
                    # aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(authority_key_identifier_subject)
                    aki = x509.AuthorityKeyIdentifier(authority_key_identifier_subject.digest, None, None)
                else:
                    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key_identifier_public)    
            if authority_key_identifier and authority_identifier:
                aki = x509.AuthorityKeyIdentifier(aki.key_identifier, [x509.DirectoryName(authority_key_identifier_issuer)], authority_key_identifier_serial)
            elif authority_identifier:
                aki = x509.AuthorityKeyIdentifier(None, [x509.DirectoryName(authority_key_identifier_issuer)], authority_key_identifier_serial)
            builder = builder.add_extension(aki, critical=False)

    private_key = serialization.load_pem_private_key(
        bytes(str(issuer_private_key).encode('utf-8')),
        password=None,
        backend=default_backend()
    )

    cert = builder.sign(private_key, hashes.SHA256(), default_backend())

    cert_pem = cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode('utf-8')

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # would like to use PKCS8 but AWS ELBs don't like it
        encryption_algorithm=serialization.NoEncryption()
    )

    return cert_pem, private_key_pem, chain_cert_pem


def issue_certificate(csr, options):

    """
    options looks like:
    2017-01-04 19:03:45,414 DEBUG: Issuing new cryptography certificate with options: <cryptography.hazmat.backends.openssl.x509._CertificateSigningRequest object at 0x7f5776648e50> {'replacements': [], 'description': u'testcert', 'roles': [], 'creator': u'lemur@nobody', 'country': u'US', 'owner': u'nschelly@dyn.com', 'authority': Authority(name=TestCA), 'validity_years': 1, 'validity_end': <Arrow [2018-01-04T19:03:45.343939+00:00]>, 'notifications': [Notification(label=DEFAULT_NSCHELLY_30_DAY), Notification(label=DEFAULT_NSCHELLY_15_DAY), Notification(label=DEFAULT_NSCHELLY_2_DAY), Notification(label=DEFAULT_SECURITY_30_DAY), Notification(label=DEFAULT_SECURITY_15_DAY), Notification(label=DEFAULT_SECURITY_2_DAY)], 'state': u'NH', 'organizational_unit': u'Engineering', 'location': u'Manchester', 'extensions': {'sub_alt_names': {'names': [{'name_type': u'DNSName', 'value': u'blah2'}]}, 'extended_key_usage': {'use_client_authentication': True, 'use_eap_over_lan': True, 'use_ocsp_signing': True, 'use_timestamping': True, 'use_server_authentication': True, 'use_eap_over_ppp': True}, 'authority_key_identifier': {'use_key_identifier': True}, 'basic_constraints': {}, 'custom': [], 'subject_key_identifier': {'include_ski': True}, 'certificate_info_access': {'include_aia': True}, 'key_usage': {'use_key_encipherment': True, 'use_non_repudiation': True, 'use_digital_signature': True, 'use_decipher_only': True, 'use_crl_sign': True, 'use_encipher_only': True, 'use_data_encipherment': True}, 'authority_identifier': {'use_authority_cert': True}}, 'validity_start': <Arrow [2017-01-04T19:03:45.343939+00:00]>, 'common_name': u'testcert', 'organization': u'Dynamic Network Services, Inc', 'name': u'testcert', 'destinations': []} [in /home/lemur/app/lemur/plugins/lemur_cryptography/plugin.py:113]
    Use options like https://github.com/Netflix/lemur/blob/master/lemur/certificates/service.py#L335
    Add to CSR like: https://cryptography.io/en/latest/x509/reference/#x-509-csr-certificate-signing-request-builder-object
    """

    csr = x509.load_pem_x509_csr(csr, default_backend())

    builder = x509.CertificateBuilder(
        issuer_name=options['authority'].authority_certificate.subject,
        subject_name=csr.subject,
        public_key=csr.public_key(),
        not_valid_before=options['validity_start'],
        not_valid_after=options['validity_end'],
        extensions=csr.extensions._extensions)

    # TODO figure out a better way to increment serial
    builder = builder.serial_number(int(uuid.uuid4()))

    private_key = serialization.load_pem_private_key(
        bytes(str(options['authority'].authority_certificate.private_key).encode('utf-8')),
        password=None,
        backend=default_backend()
    )

    cert = builder.sign(private_key, hashes.SHA256(), default_backend())

    return cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode('utf-8')


class CryptographyIssuerPlugin(IssuerPlugin):
    title = 'Cryptography'
    slug = 'cryptography-issuer'
    description = 'Enables the creation and signing of self-signed certificates'
    version = cryptography_issuer.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur.git'

    def create_certificate(self, csr, options):
        """
        Creates a certificate.

        :param csr:
        :param options:
        :return: :raise Exception:
        """
        current_app.logger.debug("Issuing new cryptography certificate with options: {0}".format(options))
        cert = issue_certificate(csr, options)
        return cert, ""

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        current_app.logger.debug("Issuing new cryptography authority with options: {0}".format(options))
        cert, private_key, chain_cert_pem = build_certificate_authority(options)
        roles = [
            {'username': '', 'password': '', 'name': options['name'] + '_admin'},
            {'username': '', 'password': '', 'name': options['name'] + '_operator'}
        ]
        return cert, private_key, chain_cert_pem, roles
