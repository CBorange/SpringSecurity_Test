package com.example.SecuritySample.repository;

import com.example.SecuritySample.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, String> {
}
