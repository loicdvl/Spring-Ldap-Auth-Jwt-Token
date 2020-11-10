package com.loicdev.springdemo.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.loicdev.springdemo.domain.Vendor;

public interface VendorRepository extends JpaRepository<Vendor, Long> {

	Optional<Vendor> findByName(String name);
}
