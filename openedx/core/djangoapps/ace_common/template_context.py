"""
Context dictionary for templates that use the ace_common base template.
"""


from django.conf import settings
from django.urls import NoReverseMatch, reverse

from edxmako.shortcuts import marketing_link
from openedx.core.djangoapps.theming.helpers import get_config_value_from_site_or_settings

from logging import getLogger

logger = getLogger(__name__)  # pylint: disable=invalid-name


def get_base_template_context(site):
    """
    Dict with entries needed for all templates that use the base template.
    """
    # When on LMS and a dashboard is available, use that as the dashboard url.
    # Otherwise, use the home url instead.
    try:
        dashboard_url = reverse('dashboard')
    except NoReverseMatch:
        dashboard_url = reverse('home')

    logger.info("PIERRE PIERRE PIERRE")
    logger.info("get_base_template_context has CONTACT_MAILING_ADDRESS as %s", get_config_value_from_site_or_settings('CONTACT_MAILING_ADDRESS', site=site, site_config_name='contact_mailing_address'))
    logger.info("PIERRE PIERRE PIERRE")

    return {
        # Platform information
        'homepage_url': 'https://cours-virginie.edulib.org/',
        'dashboard_url': 'https://cours-virginie.edulib.org/dashboard/',
        'template_revision': getattr(settings, 'EDX_PLATFORM_REVISION', None),
        'platform_name': get_config_value_from_site_or_settings(
            'PLATFORM_NAME',
            site=site,
            site_config_name='platform_name',
        ),
        'contact_email': get_config_value_from_site_or_settings(
            'CONTACT_EMAIL', site=site, site_config_name='contact_email'),
        'contact_mailing_address': get_config_value_from_site_or_settings(
            'CONTACT_MAILING_ADDRESS', site=site, site_config_name='contact_mailing_address'),
        'social_media_urls': get_config_value_from_site_or_settings('SOCIAL_MEDIA_FOOTER_URLS', site=site),
        'mobile_store_urls': get_config_value_from_site_or_settings('MOBILE_STORE_URLS', site=site),
    }
