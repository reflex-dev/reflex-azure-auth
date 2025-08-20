"""Shared types and helpers for Azure user info."""

from typing import TypedDict


class AzureUserInfo(TypedDict):
    """TypedDict representing user information from Azure / Microsoft identity platform.

    Contains user profile data returned by the /userinfo endpoint following
    successful authentication (OpenID Connect standard claims).
    """

    sub: str
    email: str | None
    name: str | None
    given_name: str | None
    middle_name: str | None
    family_name: str | None
    picture: str | None
    locale: str | None


# Microsoft API returns these without the underscore... not sure why
user_info_mapping = {
    "givenname": "given_name",
    "middlename": "middle_name",
    "familyname": "family_name",
}


def user_info_from_dict(data: dict) -> AzureUserInfo:
    """Convert a dictionary to an AzureUserInfo object."""
    for mapped_name, real_name in user_info_mapping.items():
        if mapped_name in data and real_name not in data:
            data[real_name] = data.pop(mapped_name)
    return AzureUserInfo(
        sub=data["sub"],
        email=data.get("email"),
        name=data.get("name"),
        given_name=data.get("given_name"),
        middle_name=data.get("middle_name"),
        family_name=data.get("family_name"),
        picture=data.get("picture"),
        locale=data.get("locale"),
    )
