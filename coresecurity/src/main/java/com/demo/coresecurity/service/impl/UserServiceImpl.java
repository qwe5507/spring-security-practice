package com.demo.coresecurity.service.impl;

import com.demo.coresecurity.domain.Account;
import com.demo.coresecurity.repository.UserRepository;
import com.demo.coresecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
