package com.demo.coresecurity.repository;

import com.demo.coresecurity.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {
    
}
