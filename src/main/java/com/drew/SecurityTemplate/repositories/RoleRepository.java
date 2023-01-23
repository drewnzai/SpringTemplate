package com.drew.SecurityTemplate.repositories;

import com.drew.SecurityTemplate.models.ERole;
import com.drew.SecurityTemplate.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
