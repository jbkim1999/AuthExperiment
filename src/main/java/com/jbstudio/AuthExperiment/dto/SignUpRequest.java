package com.jbstudio.AuthExperiment.dto;

public record SignUpRequest(
        String username,
        String email,
        String password
) { }
