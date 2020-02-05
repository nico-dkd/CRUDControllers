
import Vapor
import Crypto

final class UsersController: RouteCollection {
   
    func boot(router: Router) throws {
        let usersRoute = router.grouped("api", "users")

        let basicAuthMiddleware = User.basicAuthMiddleware(using: BCryptDigest())
        let guardAuthMiddleware = User.guardAuthMiddleware()

        let basicProtected = usersRoute.grouped(basicAuthMiddleware, guardAuthMiddleware)
        basicProtected.post("login", use: loginHandler)

        let tokenAuthMiddleware = User.tokenAuthMiddleware()
        let tokenProtected = usersRoute.grouped(tokenAuthMiddleware, guardAuthMiddleware)
        tokenProtected.get(use: getAllHandler)
        tokenProtected.get(User.parameter, use: getOneHandler)
        tokenProtected.put(User.parameter, use: updateHandler)
        tokenProtected.post(use: createHandler)
        tokenProtected.delete(User.parameter, use: deleteHandler)
    }
    
    func loginHandler(_ req: Request) throws -> Future<Token> {
        let user = try req.requireAuthenticated(User.self)
        let token = try Token.generate(for: user)
        print(user.name)
        return token.create(on: req)
    }
    
    func createHandler(_ req: Request) throws -> Future<User> {
    
        return try req.content.decode(User.self).flatMap { (user) in
            user.password = try BCrypt.hash(user.password)
            return user.create(on: req)
        }
    }

    func getAllHandler(_ req: Request) throws -> Future<[User]> {
         
        return User.query(on: req).decode(User.self).all()
    }
    
    func getOneHandler(_ req: Request) throws -> Future<User.PublicUser> {
    
        return try req.parameters.next(User.self).toPublic()
    }
    
    func updateHandler(_ req: Request) throws -> Future<User.PublicUser> {
     
        return try flatMap(to: User.PublicUser.self, req.parameters.next(User.self), req.content.decode(User.self)) { (user, updatedUser) in
       
            user.name = updatedUser.name
            user.username = updatedUser.username
            user.password = try BCrypt.hash(updatedUser.password)
            return user.save(on: req).toPublic()
        }
    }
    
    func deleteHandler(_ req: Request) throws -> Future<HTTPStatus> {
     
        return try req.parameters.next(User.self).flatMap { (user) in
        
            return user.delete(on: req).transform(to: HTTPStatus.noContent)
        }
    }
}
