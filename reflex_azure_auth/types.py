"""Shared types and helpers for Azure user info."""

from typing import Required, TypedDict


class AzureUserInfo(TypedDict, total=False):
    """TypedDict representing user information from Azure / Microsoft identity platform.

    Contains user profile data returned by the /userinfo endpoint following
    successful authentication (OpenID Connect standard claims).
    """

    sub: Required[str]
    email: str
    name: str
    given_name: str
    middle_name: str
    family_name: str
    picture: str
    locale: str


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
    return AzureUserInfo(**data)
