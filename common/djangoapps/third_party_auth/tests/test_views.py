"""
Test the views served by third_party_auth.
"""
# pylint: disable=no-member
import ddt
from lxml import etree
from onelogin.saml2.errors import OneLogin_Saml2_Error
import unittest
from .testutil import AUTH_FEATURE_ENABLED, SAMLTestCase

# Define some XML namespaces:
from third_party_auth.tasks import SAML_XML_NS
XMLDSIG_XML_NS = 'http://www.w3.org/2000/09/xmldsig#'


@unittest.skipUnless(AUTH_FEATURE_ENABLED, 'third_party_auth not enabled')
@ddt.ddt
class SAMLMetadataTest(SAMLTestCase):
    """
    Test the SAML metadata view
    """
    METADATA_URL = '/auth/saml/metadata.xml'

    def test_saml_disabled(self):
        """ When SAML is not enabled, the metadata view should return 404 """
        self.enable_saml(enabled=False)
        response = self.client.get(self.METADATA_URL)
        self.assertEqual(response.status_code, 404)

    def test_metadata(self):
        self.enable_saml(
            private_key=self._get_private_key(key_name),
            public_key=self._get_public_key(key_name),
            entity_id="https://saml.example.none",
        )
        doc = self._fetch_metadata()
        # Check the ACS URL:
        acs_node = doc.find(".//{}".format(etree.QName(SAML_XML_NS, 'AssertionConsumerService')))
        self.assertIsNotNone(acs_node)
        self.assertEqual(acs_node.attrib['Location'], 'http://example.none/auth/complete/tpa-saml/')

    @ddt.data(
        # Test two slightly different key pair export formats
        ('saml_key', 'MIICsDCCAhmgAw'),
        ('saml_key_alt', 'MIICWDCCAcGgAw'),
    )
    @ddt.unpack
    def test_signed_metadata(self, key_name, pub_key_starts_with):
        self.enable_saml(
            private_key=self._get_private_key(key_name),
            public_key=self._get_public_key(key_name),
            entity_id="https://saml.example.none",
            other_config_str='{"SECURITY_CONFIG": {"signMetadata": true} }',
        )
        self._validate_signed_metadata(pub_key_starts_with=pub_key_starts_with)

    def test_secure_key_configuration(self):
        """ Test that the SAML private key can be stored in Django settings and not the DB """
        self.enable_saml(
            public_key='',
            private_key='',
            other_config_str='{"SECURITY_CONFIG": {"signMetadata": true} }',
        )
        with self.assertRaises(OneLogin_Saml2_Error):
            self._fetch_metadata()  # OneLogin_Saml2_Error: Cannot sign metadata: missing SP private key.
        with self.settings(
            SOCIAL_AUTH_SAML_SP_PRIVATE_KEY=self._get_private_key('saml_key'),
            SOCIAL_AUTH_SAML_SP_PUBLIC_CERT=self._get_public_key('saml_key'),
        ):
            self._validate_signed_metadata()

    def _validate_signed_metadata(self, pub_key_starts_with='MIICsDCCAhmgAw'):
        """ Fetch the SAML metadata and do some validation """
        doc = self._fetch_metadata()
        sig_node = doc.find(".//{}".format(etree.QName(XMLDSIG_XML_NS, 'SignatureValue')))
        self.assertIsNotNone(sig_node)
        # Check that the right public key was used:
        pub_key_node = doc.find(".//{}".format(etree.QName(XMLDSIG_XML_NS, 'X509Certificate')))
        self.assertIsNotNone(pub_key_node)
        self.assertIn(pub_key_starts_with, pub_key_node.text)

    def _fetch_metadata(self):
        """ Fetch and parse the metadata XML at self.METADATA_URL """
        response = self.client.get(self.METADATA_URL)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/xml')
        # The result should be valid XML:
        try:
            metadata_doc = etree.fromstring(response.content)
        except etree.LxmlError:
            self.fail('SAML metadata must be valid XML')
        self.assertEqual(metadata_doc.tag, etree.QName(SAML_XML_NS, 'EntityDescriptor'))
        return metadata_doc
