package com.jbstudio.AuthExperiment.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

import com.jbstudio.AuthExperiment.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsernameOrEmail(String username, String email);
    Boolean existsByUsernameOrEmail(String username, String email);

    // For refresh token management
    // Optional<User> findByRefreshToken(String refreshToken);
}
