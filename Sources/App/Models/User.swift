import Vapor
import FluentSQLite
import Authentication

final class User: Codable {

    var id: Int?
    var name: String
    var username: String
    var password: String
    
    init(name: String, username: String, password: String) {
        self.name = name
        self.username = username
        self.password = password
    }
    
    final class PublicUser: Codable {
        
        var id: Int?
        var name: String
        var username: String
        
        init(id: Int?, name: String, username: String) {
            
            self.id = id
            self.name = name
            self.username = username
        }
    }
}

extension User: SQLiteModel {}

extension User: Content {}
extension User: Parameter {}
extension User.PublicUser: Content {}

extension User {
    
    func toPublic() -> User.PublicUser {
    
       return User.PublicUser(id: id, name: name, username: username)
    }
}

extension Future where T: User {
    
    func toPublic() -> Future<User.PublicUser> {
    
        return map(to: User.PublicUser.self) { (user) in
        
            return user.toPublic()
        }
    }
}

extension User: BasicAuthenticatable {
    static var usernameKey: UsernameKey {
        return \User.username
    }

    static var passwordKey: PasswordKey {
        return \User.password
    }
}

extension User: Migration {
    
    static func prepare(on conn: SQLiteConnection) -> Future<Void> {
    
        return Database.create(self, on: conn) { (builder) in
        
            try addProperties(to: builder)
            builder.unique(on: \.username)
        }
    }
}

struct AdminUser: Migration {
    
    typealias Database = SQLiteDatabase

    static func prepare(on conn: SQLiteConnection) -> Future<Void> {
        let password = try? BCrypt.hash("password") // NOT do this for production
        guard let hashedPassword = password else {
            fatalError("Failed to create admin user")
        }

        let user = User(name: "Admin", username: "admin", password: hashedPassword)
        return user.save(on: conn).transform(to: ())
    }

    static func revert(on conn: SQLiteConnection) -> Future<Void> {
        return .done(on: conn)
    }
}

extension User: TokenAuthenticatable {
    typealias TokenType = Token
}
