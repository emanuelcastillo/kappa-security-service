package com.kappa.security.repository;

import com.kappa.security.entity.PartnerEntity;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface PartnersRepository extends CrudRepository<PartnerEntity, Long> {
    Optional<PartnerEntity> findByClientId(String  clientId);
}
