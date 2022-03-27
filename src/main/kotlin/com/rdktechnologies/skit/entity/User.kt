package com.rdktechnologies.skit.entity

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import javax.persistence.*

@Entity
@Table(name = "users")
@JsonIgnoreProperties(
        "favouritePosts",
        "likedPosts",
        "roles",
        "password",
        "isEnabled",
        "isAccountNonExpired",
        "isAccountNonLocked",
        "isCredentialsNonExpired",
        "isNotificationEnabled",
        "isFacebookLogin","followers","following"
)
data class User(

        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        var id: Long? = null,
        var firstName: String? = null,
        var lastName: String? = null,
        var email: String? = null,
        var picUrl:String?=null,
        var password: String? = null,
        var isEnabled: Boolean? = null,
        var isAccountNonExpired: Boolean? = null,
        var isAccountNonLocked: Boolean? = null,
        var isCredentialsNonExpired: Boolean? = null,
        var isNotificationEnabled: Boolean? = true,
        var isFacebookLogin: Boolean? = false,
        @OneToOne(cascade = [CascadeType.ALL])
        var roles: Role? = null

)
