from django.utils.html import escape


def render_bio(profile):
    bio = profile.get("bio", "")
    return escape(bio)
