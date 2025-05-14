# secure_channel/templatetags/string_filters.py
from django import template
import os
from django.utils import timezone
from datetime import timedelta

register = template.Library()

@register.filter
def endswith(value, arg):
    return str(value).endswith(arg)

@register.filter
def is_large(file_obj):
    try:
        return file_obj.size > 5 * 1024 * 1024  # 5 MB
    except:
        return False

@register.filter
def is_expired(expired_at):
    from django.utils.timezone import now
    if expired_at is None:
        return False
    return now() > expired_at


@register.filter
def strip_uuid(value):
    """
    Removes UUID prefix before underscore (_) in filename.
    """
    return value.split('_', 1)[1] if '_' in value else value

