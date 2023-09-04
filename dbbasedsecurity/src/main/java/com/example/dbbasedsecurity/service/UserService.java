package com.example.dbbasedsecurity.service;

import com.example.dbbasedsecurity.domain.dto.AccountDto;
import com.example.dbbasedsecurity.domain.entity.Account;

import java.util.List;

public interface UserService {

    void createUser(Account account);

    void modifyUser(AccountDto accountDto);

    List<Account> getUsers();

    AccountDto getUser(Long id);

    void deleteUser(Long idx);
}
