package edu.nu.owaspapivulnlab.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import edu.nu.owaspapivulnlab.model.AppUser;

import java.util.List;
import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByUsername(String username);

    @Query("select u.id from AppUser u where u.username = :username")
    Optional<Long> findIdByUsername(@Param("username") String username);

    boolean existsByIdAndUsername(Long id, String username);
    Optional<AppUser> findByIdAndUsername(Long id, String username);

    // VULNERABILITY(API9: Improper Inventory/SQLi exemplar using JPQL concatenation via SpEL workaround in controller)
    @Query("select u from AppUser u where u.username like %?1% or u.email like %?1%")
    List<AppUser> search(String q);

}
