"""
Third-party auth provider configuration API.
"""
from django.contrib.sites.models import Site
from openedx.core.djangoapps.theming.helpers import get_current_request

from .models import (
    OAuth2ProviderConfig, SAMLConfiguration, SAMLProviderConfig, LTIProviderConfig,
    _PSA_OAUTH2_BACKENDS, _PSA_SAML_BACKENDS, _LTI_BACKENDS,
)

from social.backends import twitter, google, linkedin, facebook

_DEFAULT_ICON_CLASS = 'icon-signin'


class BaseProvider(object):
    """Abstract base class for third-party auth providers.

    All providers must subclass BaseProvider -- otherwise, they cannot be put
    in the provider Registry.
    """

    # Class. The provider's backing social.backends.base.BaseAuth child.
    BACKEND_CLASS = None
    # String. Name of the FontAwesome glyph to use for sign in buttons (or the
    # name of a user-supplied custom glyph that is present at runtime).
    ICON_CLASS = _DEFAULT_ICON_CLASS
    # String. User-facing name of the provider. Must be unique across all
    # enabled providers. Will be presented in the UI.
    NAME = None
    # Dict of string -> object. Settings that will be merged into Django's
    # settings instance. In most cases the value will be None, since real
    # values are merged from .json files (foo.auth.json; foo.env.json) onto the
    # settings instance during application initialization.
    SETTINGS = {}

    @classmethod
    def get_authentication_backend(cls):
        """Gets associated Django settings.AUTHENTICATION_BACKEND string."""
        return '%s.%s' % (cls.BACKEND_CLASS.__module__, cls.BACKEND_CLASS.__name__)

    @classmethod
    def get_email(cls, unused_provider_details):
        """Gets user's email address.

        Provider responses can contain arbitrary data. This method can be
        overridden to extract an email address from the provider details
        extracted by the social_details pipeline step.

        Args:
            unused_provider_details: dict of string -> string. Data about the
                user passed back by the provider.

        Returns:
            String or None. The user's email address, if any.
        """
        return None

    @classmethod
    def get_name(cls, unused_provider_details):
        """Gets user's name.

        Provider responses can contain arbitrary data. This method can be
        overridden to extract a full name for a user from the provider details
        extracted by the social_details pipeline step.

        Args:
            unused_provider_details: dict of string -> string. Data about the
                user passed back by the provider.

        Returns:
            String or None. The user's full name, if any.
        """
        return None

    @classmethod
    def get_register_form_data(cls, pipeline_kwargs):
        """Gets dict of data to display on the register form.

        common.djangoapps.student.views.register_user uses this to populate the
        new account creation form with values supplied by the user's chosen
        provider, preventing duplicate data entry.

        Args:
            pipeline_kwargs: dict of string -> object. Keyword arguments
                accumulated by the pipeline thus far.

        Returns:
            Dict of string -> string. Keys are names of form fields; values are
            values for that field. Where there is no value, the empty string
            must be used.
        """
        # Details about the user sent back from the provider.
        details = pipeline_kwargs.get('details')

        # Get the username separately to take advantage of the de-duping logic
        # built into the pipeline. The provider cannot de-dupe because it can't
        # check the state of taken usernames in our system. Note that there is
        # technically a data race between the creation of this value and the
        # creation of the user object, so it is still possible for users to get
        # an error on submit.
        suggested_username = pipeline_kwargs.get('username')

        return {
            'email': cls.get_email(details) or '',
            'name': cls.get_name(details) or '',
            'username': suggested_username,
        }

    @classmethod
    def merge_onto(cls, settings):
        """Merge class-level settings onto a django settings module."""
        for key, value in cls.SETTINGS.iteritems():
            setattr(settings, key, value)

class GoogleOauth2(BaseProvider):
    """Provider for Google's Oauth2 auth system."""

    BACKEND_CLASS = google.GoogleOAuth2
    ICON_CLASS = 'icon-google-plus'
    NAME = 'Google'
    SETTINGS = {
        'SOCIAL_AUTH_GOOGLE_OAUTH2_KEY': None,
        'SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET': None,
    }

    @classmethod
    def get_email(cls, provider_details):
        return provider_details.get('email')

    @classmethod
    def get_name(cls, provider_details):
        return provider_details.get('fullname')


class LinkedInOauth2(BaseProvider):
    """Provider for LinkedIn's Oauth2 auth system."""

    BACKEND_CLASS = linkedin.LinkedinOAuth2
    ICON_CLASS = 'icon-linkedin'
    NAME = 'LinkedIn'
    SETTINGS = {
        'SOCIAL_AUTH_LINKEDIN_OAUTH2_KEY': None,
        'SOCIAL_AUTH_LINKEDIN_OAUTH2_SECRET': None,
    }

    @classmethod
    def get_email(cls, provider_details):
        return provider_details.get('email')

    @classmethod
    def get_name(cls, provider_details):
        return provider_details.get('fullname')


class FacebookOauth2(BaseProvider):
    """Provider for LinkedIn's Oauth2 auth system."""

    BACKEND_CLASS = facebook.FacebookOAuth2
    ICON_CLASS = 'icon-facebook'
    NAME = 'Facebook'
    SETTINGS = {
        'SOCIAL_AUTH_FACEBOOK_KEY': None,
        'SOCIAL_AUTH_FACEBOOK_SECRET': None,
    }

    @classmethod
    def get_email(cls, provider_details):
        return provider_details.get('email')

    @classmethod
    def get_name(cls, provider_details):
        return provider_details.get('fullname')

class TwitterOauth(BaseProvider):
    """Provider for LinkedIn's Oauth2 auth system."""

    BACKEND_CLASS = twitter.TwitterOAuth
    ICON_CLASS = 'icon-twitter'
    NAME = 'Twitter'
    SETTINGS = {
        'SOCIAL_AUTH_TWITTER_KEY': None,
        'SOCIAL_AUTH_TWITTER_SECRET': None,
    }

    @classmethod
    def get_email(cls, provider_details):
        return provider_details.get('email')

    @classmethod
    def get_name(cls, provider_details):
        return provider_details.get('fullname')



class Registry(object):
    """
    API for querying third-party auth ProviderConfig objects.

    Providers must subclass ProviderConfig in order to be usable in the registry.
    """
    @classmethod
    def _enabled_providers(cls):
        """
        Helper method that returns a generator used to iterate over all providers
        of the current site.
        """
        for backend_name in _PSA_OAUTH2_BACKENDS:
            provider = OAuth2ProviderConfig.current(backend_name)
            if provider.enabled_for_current_site:
                yield provider
        if SAMLConfiguration.is_enabled(Site.objects.get_current(get_current_request())):
            idp_slugs = SAMLProviderConfig.key_values('idp_slug', flat=True)
            for idp_slug in idp_slugs:
                provider = SAMLProviderConfig.current(idp_slug)
                if provider.enabled_for_current_site and provider.backend_name in _PSA_SAML_BACKENDS:
                    yield provider
        for consumer_key in LTIProviderConfig.key_values('lti_consumer_key', flat=True):
            provider = LTIProviderConfig.current(consumer_key)
            if provider.enabled_for_current_site and provider.backend_name in _LTI_BACKENDS:
                yield provider

    @classmethod
    def enabled(cls):
        """Returns list of enabled providers."""
        return sorted(cls._enabled_providers(), key=lambda provider: provider.name)

    @classmethod
    def displayed_for_login(cls):
        """Returns list of providers that can be used to initiate logins in the UI"""
        return [provider for provider in cls.enabled() if provider.display_for_login]

    @classmethod
    def get(cls, provider_id):
        """Gets provider by provider_id string if enabled, else None."""
        if '-' not in provider_id:  # Check format - see models.py:ProviderConfig
            raise ValueError("Invalid provider_id. Expect something like oa2-google")
        try:
            return next(provider for provider in cls._enabled_providers() if provider.provider_id == provider_id)
        except StopIteration:
            return None

    @classmethod
    def get_from_pipeline(cls, running_pipeline):
        """Gets the provider that is being used for the specified pipeline (or None).

        Args:
            running_pipeline: The python-social-auth pipeline being used to
                authenticate a user.

        Returns:
            An instance of ProviderConfig or None.
        """
        for enabled in cls._enabled_providers():
            if enabled.is_active_for_pipeline(running_pipeline):
                return enabled

    @classmethod
    def get_enabled_by_backend_name(cls, backend_name):
        """Generator returning all enabled providers that use the specified
        backend on the current site.

        Example:
            >>> list(get_enabled_by_backend_name("tpa-saml"))
                [<SAMLProviderConfig>, <SAMLProviderConfig>]

        Args:
            backend_name: The name of a python-social-auth backend used by
                one or more providers.

        Yields:
            Instances of ProviderConfig.
        """
        if backend_name in _PSA_OAUTH2_BACKENDS:
            provider = OAuth2ProviderConfig.current(backend_name)
            if provider.enabled_for_current_site:
                yield provider
        elif backend_name in _PSA_SAML_BACKENDS and SAMLConfiguration.is_enabled(
                Site.objects.get_current(get_current_request())):
            idp_names = SAMLProviderConfig.key_values('idp_slug', flat=True)
            for idp_name in idp_names:
                provider = SAMLProviderConfig.current(idp_name)
                if provider.backend_name == backend_name and provider.enabled_for_current_site:
                    yield provider
        elif backend_name in _LTI_BACKENDS:
            for consumer_key in LTIProviderConfig.key_values('lti_consumer_key', flat=True):
                provider = LTIProviderConfig.current(consumer_key)
                if provider.backend_name == backend_name and provider.enabled_for_current_site:
                    yield provider
