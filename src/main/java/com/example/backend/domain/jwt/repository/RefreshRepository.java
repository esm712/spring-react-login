package com.example.backend.domain.jwt.repository;

import com.example.backend.domain.jwt.entity.RefreshEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {
}
