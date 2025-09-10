package in.harshbisht.authify.service;

import in.harshbisht.authify.io.ProfileRequest;
import in.harshbisht.authify.io.ProfileResponse;

public interface ProfileService {

    ProfileResponse createProfile(ProfileRequest request);

    ProfileResponse getProfile(String email);
}
