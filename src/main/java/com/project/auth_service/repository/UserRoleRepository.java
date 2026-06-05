package com.project.auth_service.repository;

import com.project.auth_service.entity.UserRoleEntity;
import com.project.auth_service.entity.UserRoleId;
import com.project.auth_service.enums.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRoleEntity, UserRoleId> {

    @Query("select ur.id.role from UserRoleEntity ur where ur.id.userId = :userId")
    List<Role> findRolesByUserId(@Param("userId") Long userId);

    @Query("""
            select ur.id.userId as userId,
                   ur.id.role as role
            from UserRoleEntity ur
            where ur.id.userId in :userIds
            """)
    List<UserRoleView> findRolesByUserIds(@Param("userIds") Collection<Long> userIds);

    @Query("select count(ur) from UserRoleEntity ur where ur.id.role = :role")
    long countByRole(@Param("role") Role role);

    interface UserRoleView {
        Long getUserId();

        Role getRole();
    }
}
