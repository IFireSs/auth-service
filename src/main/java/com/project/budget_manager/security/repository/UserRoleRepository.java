package com.project.budget_manager.security.repository;

import com.project.budget_manager.security.entity.UserRoleEntity;
import com.project.budget_manager.security.entity.UserRoleId;
import com.project.budget_manager.security.enums.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRoleEntity, UserRoleId> {

    @Query("select ur.id.role from UserRoleEntity ur where ur.id.userId = :userId")
    List<Role> findRolesByUserId(@Param("userId") Long userId);
}