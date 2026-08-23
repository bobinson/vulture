from django.utils.safestring import mark_safe


def render_bio(profile):
    bio = profile.get("bio", "")
    return mark_safe(bio)
