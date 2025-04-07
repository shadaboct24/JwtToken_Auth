import java.util.ArrayList;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.cdac.tdu.app.entity.TAssignRoles;
import com.cdac.tdu.app.entity.TEmployee;
import com.cdac.tdu.app.entity.TRole;
import com.cdac.tdu.app.repository.TAssignRolesRepo;
import com.cdac.tdu.app.repository.TEmployeeRepo;
import com.cdac.tdu.app.repository.TRoleAuthorizeRepo;
import com.cdac.tdu.app.repository.TRoleRepo;

@Service
public class TduAuthService implements UserDetailsService {

    @Autowired
    TEmployeeRepo tEmployeeRepo;

    @Autowired
    TRoleRepo tRoleRepo;

    @Autowired
    TAssignRolesRepo tAssignRolesRepo;

    @Autowired
    TRoleAuthorizeRepo tRoleAuthorizeRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        TEmployee tEmployee = tEmployeeRepo.findByEmail(username);

        System.out.println("load userName Called");

        if (tEmployee != null) {

            // ArrayList<TAssignRoles> tAssignRoles =
            // tAssignRolesRepo.findByEmail(username);

            // ArrayList<SimpleGrantedAuthority> roles = new ArrayList<>();

            // tAssignRoles.forEach(role ->{

            // Optional<TRole> trole = tRoleRepo.findById(role.getRoleId());

            // roles.add(new SimpleGrantedAuthority(trole.get().getRoleName()));

            // });

            return new User(tEmployee.getEmail(), tEmployee.getPassword(), new ArrayList<>());

        } else {
            throw new UsernameNotFoundException(username);
        }
    }

}
