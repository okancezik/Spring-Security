package com.okancezik.security.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {



    @Query(value="""
            select t from Token t inner join User u on t.user.id = u.id
            where t.user.id = :userId and (t.expired = false or t.revoked = false)
              """
    )
    List<Token> findAllValidTokenByUser(int userId);

    Optional<Token> findByToken(String token);
}
