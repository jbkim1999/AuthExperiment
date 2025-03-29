package com.jbstudio.AuthExperiment.dto;

public record LoginRequest(
        String usernameOrEmail,
        String password
) { }
