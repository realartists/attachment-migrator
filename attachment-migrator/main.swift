#!/usr/bin/xcrun swift

//
//  main.swift
//  attachment-migrator
//
//  Created by James Howard on 3/20/18.
//  Copyright © 2018 Real Artists, Inc. All rights reserved.
//

import Foundation
import SQLite3

/* Utilities */

// Hat Tip: https://gist.github.com/zwaldowski/8864f2d74fa45ee2cfa8ba0573abf4ef
private func loadCSymbol<T>(named name: String, of _: T.Type = T.self) -> T {
    let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
    guard let sym = dlsym(RTLD_DEFAULT, name) else { preconditionFailure(String(cString: dlerror())) }
    return unsafeBitCast(sym, to: T.self)
}

private let CC_SHA1_DIGEST_LENGTH = 20
private let CC_SHA1: @convention(c) (UnsafeRawPointer, Int32, UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> = loadCSymbol(named: "CC_SHA1")

extension Data {
    func sha1Sum() -> String {
        var sha = Data(repeating: 0, count: CC_SHA1_DIGEST_LENGTH)
        _ = self.withUnsafeBytes { (src) in
            _ = sha.withUnsafeMutableBytes { CC_SHA1(src, numericCast(self.count), $0) }
        }
        return sha.map { (byte) in (byte <= 0xF ? "0" : "") + String(byte, radix: 16) }.joined()
    }
}

struct APIResponse<T:Codable> {
    var value:T
    var http:HTTPURLResponse
}

extension URLRequest {
    func executeAPIRequest<Response:Codable>() throws -> APIResponse<Response> {
        let sema = DispatchSemaphore(value:0);
        let session = URLSession.shared;
        var outerError:Error? = nil
        var outerResponse:HTTPURLResponse? = nil
        var result:Response? = nil
        
        session.dataTask(with: self) { (data, response, httpError) in
            outerResponse = response as? HTTPURLResponse
            let statusCode = response != nil ? (response as! HTTPURLResponse).statusCode : 0
            if (httpError != nil) {
                outerError = httpError
            } else if (statusCode < 200 || statusCode >= 400) {
                let msg = "\(self.url!): HTTP error \(statusCode)" + (data != nil ? (" " + String(data:data!, encoding:.utf8)!) : "")
                outerError = NSError.init(domain: NSURLErrorDomain, code: URLError.Code.init(rawValue: (response as! HTTPURLResponse).statusCode).rawValue, userInfo: [NSLocalizedDescriptionKey : msg])
            } else {
                do {
                    result = try JSONDecoder().decode(Response.self, from: data!)
                } catch {
                    outerError = error
                }
            }
            
            sema.signal()
        }.resume()
        
        sema.wait()
        
        if (outerError != nil) {
            throw outerError!
        }
        
        return APIResponse<Response>(value:result!, http:outerResponse!)
    }
}

extension String {
    func wholeNSRange() -> NSRange {
        return NSMakeRange(0, self.count)
    }
}

/* For interacting with GitHub REST API */
class GitHubAPI {
    let token:String;
    
    init(_ token:String) {
        self.token = token
    }
    
    struct Patch : Codable {
        let body:String
    }
    
    func patch(endpoint:String, body:String) throws -> Void {
        var req = URLRequest(url: URL(string:"https://api.github.com/\(endpoint)")!)
        req.httpMethod = "PATCH"
        req.allHTTPHeaderFields = ["Content-Type": "application/json", "Authorization": "token \(self.token)", "Accept": "application/json"]
        req.httpBody = try JSONEncoder().encode(Patch(body:body))
        
        let _:APIResponse<Patch> = try req.executeAPIRequest()
    }
    
    func get<Response:Codable>(endpoint:String) throws -> APIResponse<Response> {
        var req = URLRequest(url: URL(string:"https://api.github.com/\(endpoint)")!)
        req.httpMethod = "GET"
        req.allHTTPHeaderFields = ["Content-Type": "application/json", "Authorization": "token \(self.token)", "Accept": "application/json"]
        
        let response:APIResponse<Response> = try req.executeAPIRequest()
        return response
    }
    
    struct User : Codable {
        var id:Int
        var login:String
        var oauthScopes:[String]?
    }
    
    func user() throws -> User {
        var response:APIResponse<User> = try self.get(endpoint:"user")
        let scopes = (response.http.allHeaderFields["X-OAuth-Scopes"] as? String)?.components(separatedBy: ", ")
        response.value.oauthScopes = scopes
        return response.value
    }
}

// Represents types of GitHub objects that we can migrate attachments for
protocol Migratable {
    func url() -> URL
    func patchEndpoint() -> String
    
    var body:String { get }
}

// For interacting with ship.db
class ShipDB {
    var db:OpaquePointer? = nil
    
    init(path:String) throws {
        let result = sqlite3_open(path, &db)
        if (result != SQLITE_OK) {
            throw NSError(domain: "SQL", code: Int(result), userInfo: [NSLocalizedDescriptionKey:"Unable to open database at path \(path): \(String(cString: sqlite3_errstr(result)))"])
        }
    }
    
    deinit {
        if (db != nil) {
            sqlite3_close_v2(db)
        }
    }
    
    struct Issue : Migratable {
        let id:Int
        let number:Int
        let body:String
        let user:GitHubAPI.User
        let repoFullName:String
        
        func url() -> URL {
            return URL(string: "https://github.com/\(repoFullName)/issues/\(number)")!
        }
        
        func patchEndpoint() -> String {
            return "repos/\(repoFullName)/issues/\(number)"
        }
    }
    
    func prepare(_ sql:String, _ authoredBy:String?) -> OpaquePointer? {
        var sql = sql
        
        if (authoredBy != nil) {
            sql += " AND ZLOCALACCOUNT.ZLOGIN = ?"
        }
        
        var pstmt:OpaquePointer? = nil
        sqlite3_prepare(db, sql, -1, &pstmt, nil);
        
        if (authoredBy != nil) {
            sqlite3_bind_text(pstmt, 1, authoredBy!, -1, nil)
        }
        
        return pstmt;
    }
    
    func issuesToBeMigrated(authoredBy:String?) -> [Issue] {
        let sql = """
SELECT ZLOCALISSUE.ZIDENTIFIER,
       ZLOCALISSUE.ZNUMBER,
       ZLOCALISSUE.ZBODY,
       ZLOCALACCOUNT.ZIDENTIFIER,
       ZLOCALACCOUNT.ZLOGIN,
       ZLOCALREPO.ZFULLNAME
  FROM ZLOCALISSUE
  JOIN ZLOCALACCOUNT ON (ZLOCALACCOUNT.Z_PK = ZLOCALISSUE.ZORIGINATOR)
  JOIN ZLOCALREPO ON (ZLOCALREPO.Z_PK = ZLOCALISSUE.ZREPOSITORY)
 WHERE ZLOCALISSUE.ZBODY LIKE '%https://shipusercontent.com%'
"""
        
        let pstmt = self.prepare(sql, authoredBy)
        
        var issues:[Issue] = []
        while (sqlite3_step(pstmt) == SQLITE_ROW) {
            let i = Issue(id: Int(sqlite3_column_int64(pstmt, 0)),
                          number: Int(sqlite3_column_int64(pstmt, 1)),
                          body: String(cString: sqlite3_column_text(pstmt, 2)!),
                          user: GitHubAPI.User(id: Int(sqlite3_column_int64(pstmt, 3)),
                                               login: String(cString: sqlite3_column_text(pstmt, 4)!),
                                               oauthScopes: nil),
                          repoFullName: String(cString: sqlite3_column_text(pstmt, 5)))
            issues.append(i)
        }
        
        sqlite3_finalize(pstmt)
        
        return issues
    }
    
    struct Comment : Migratable {
        let id:Int
        let body:String
        let issueNumber:Int
        let user:GitHubAPI.User
        let repoFullName:String
        
        enum CommentType {
            case Issue
            case Review
        }
        let type:CommentType
        
        func url() -> URL {
            switch type {
            case .Issue:
                return URL(string: "https://github.com/\(repoFullName)/issues/\(issueNumber)#issuecomment-\(id)")!
            case .Review:
                return URL(string: "https://github.com/\(repoFullName)/pull/\(issueNumber)#discussion_r\(id)")!
            }
        }
        
        func patchEndpoint() -> String {
            switch type {
            case .Issue:
                return "repos/\(repoFullName)/issues/comments/\(id)"
            case .Review:
                return "repos/\(repoFullName)/pulls/comments/\(id)"
            }
        }
    }
    
    func commentsToBeMigrated(table:String, authoredBy:String?, type:Comment.CommentType) -> [Comment] {
        let sql = """
SELECT \(table).ZIDENTIFIER,
       \(table).ZBODY,
       ZLOCALISSUE.ZNUMBER,
       ZLOCALACCOUNT.ZIDENTIFIER,
       ZLOCALACCOUNT.ZLOGIN,
       ZLOCALREPO.ZFULLNAME
  FROM \(table)
  JOIN ZLOCALISSUE ON (ZLOCALISSUE.Z_PK = \(table).ZISSUE)
  JOIN ZLOCALACCOUNT ON (ZLOCALACCOUNT.Z_PK = \(table).ZUSER)
  JOIN ZLOCALREPO ON (ZLOCALREPO.Z_PK = ZLOCALISSUE.ZREPOSITORY)
 WHERE \(table).ZBODY LIKE '%https://shipusercontent.com%'
"""
        let pstmt = self.prepare(sql, authoredBy)
        
        var comments:[Comment] = []
        while (sqlite3_step(pstmt) == SQLITE_ROW) {
            let c = Comment(id: Int(sqlite3_column_int64(pstmt, 0)),
                            body: String(cString: sqlite3_column_text(pstmt, 1)),
                            issueNumber: Int(sqlite3_column_int64(pstmt, 2)),
                            user: GitHubAPI.User(id: Int(sqlite3_column_int64(pstmt, 3)),
                                                 login: String(cString: sqlite3_column_text(pstmt, 4)!),
                                                 oauthScopes: nil),
                            repoFullName: String(cString: sqlite3_column_text(pstmt, 5)),
                            type: type)
            comments.append(c)
        }
        
        return comments
    }
    
    func issueCommentsToBeMigrated(authoredBy:String?) -> [Comment] {
        return commentsToBeMigrated(table: "ZLOCALCOMMENT", authoredBy: authoredBy, type: .Issue)
    }
    
    func reviewCommentsToBeMigrated(authoredBy:String?) -> [Comment] {
        return commentsToBeMigrated(table: "ZLOCALPRCOMMENT", authoredBy: authoredBy, type: .Review)
    }
}

// Abstract base class of all attachment migrators. Handles actually moving attachments from shipusercontent.com to elsewhere.
class AttachmentMigrator {
    func validateMigration(src:String, dst:String) throws -> Void {
        let srcURL = URL(string:src)
        let dstURL = URL(string:dst)
        if (srcURL == nil) {
            throw NSError(domain:"migrator", code:0, userInfo: [NSLocalizedDescriptionKey:"Invalid src URL: \(src)"])
        }
        if (dstURL == nil) {
            throw NSError(domain:"migrator", code:0, userInfo: [NSLocalizedDescriptionKey:"Unknown dst URL: \(dst)"])
        }
        
        var srcError:Error? = nil
        var srcHash:String? = nil
        var dstError:Error? = nil
        var dstHash:String? = nil
        
        let group = DispatchGroup()
        
        group.enter()
        URLSession.shared.dataTask(with: srcURL!) { (data, response, err) in
            if (err != nil) {
                srcError = err
            } else {
                srcHash = data?.sha1Sum() ?? ""
            }
            group.leave()
            }.resume()
        
        group.enter()
        URLSession.shared.dataTask(with: srcURL!) { (data, response, err) in
            if (err != nil) {
                dstError = err
            } else {
                dstHash = data?.sha1Sum() ?? ""
            }
            group.leave()
            }.resume()
        
        group.wait()
        
        if (srcError != nil) {
            throw srcError!
        }
        if (dstError != nil) {
            throw dstError!
        }
        if (srcHash! != dstHash!) {
            throw NSError.init(domain: "migrator", code: 0, userInfo: [NSLocalizedDescriptionKey:"Hash mismatch: \(srcURL!) <\(srcHash!)> != \(dstURL!) <\(dstHash!)>"])
        }
    }
    
    func migrate(url:String) throws -> String {
        fatalError("migrate(url:) must be implemented")
    }
    
    func migrate(body:String) throws -> (String, [String: String]) {
        let re = try NSRegularExpression(pattern: "https://shipusercontent.com/[a-f0-9]{32}/[^\\s'\"\\)]+", options: NSRegularExpression.Options(rawValue:0))
        let matches = re.matches(in: body, options: NSRegularExpression.MatchingOptions(rawValue:0), range:body.wholeNSRange())
        
        var migrated = String(body)
        var urls = [String: String]()
        for match in matches.reversed() {
            let bodyRange = Range(match.range(at: 0), in:body)!
            let src = String(body[bodyRange])
            let dst = try migrate(url:src)
            
            migrated.replaceSubrange(bodyRange, with: dst)
            
            urls[src] = dst
        }
        
        return (migrated, urls)
    }
}

// Subclass of AttachmentMigrator that shells out to a subprocess to do attachment migration
class ShellMigrator : AttachmentMigrator {
    let shell:String
    
    init(shell:String) {
        self.shell = shell
    }
    
    override func migrate(url:String) throws -> String {
        let command = self.shell + " '\(url)'"
        let task = Process()
        task.launchPath = "/bin/bash"
        task.arguments = ["-c", command]
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        task.standardOutput = stdoutPipe
        task.standardError = stderrPipe
        try task.run()
        task.waitUntilExit()
        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        let stdoutStr = String(data:stdoutData, encoding:.utf8) ?? ""
        let stderrStr = String(data:stderrData, encoding:.utf8) ?? ""
        
        if (task.terminationStatus != 0) {
            throw NSError.init(domain: "shell", code: Int(task.terminationStatus), userInfo: [NSLocalizedDescriptionKey: stderrStr])
        }
        
        let dst = stdoutStr.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        
        try validateMigration(src:url, dst:dst)
        
        return dst
    }
}

// AttachmentMigrator subclass that rehosts attachments on Dropbox
class DropboxMigrator : AttachmentMigrator {
    let token:String
    
    init(token:String) {
        self.token = token
    }
    
    struct UploadRequest : Codable {
        let path:String
        let mode:String
        let autorename:Bool
    }
    
    struct UploadResponse : Codable {
        let name:String
        let id:String
        let path_lower:String
        let path_display:String
    }
    
    func upload(data:Data, args:UploadRequest) throws -> UploadResponse {
        var req = URLRequest(url:URL(string:"https://content.dropboxapi.com/2/files/upload")!)
        req.httpMethod = "POST"
        let argStr = try String(data:JSONEncoder().encode(args), encoding:.utf8)!
        req.allHTTPHeaderFields = ["Authorization": "Bearer \(self.token)", "Content-Type": "application/octet-stream", "Dropbox-API-Arg": argStr]
        req.httpBody = data
        
        let response:APIResponse<UploadResponse> = try req.executeAPIRequest()
        
        return response.value
    }
    
    func api<Request:Codable, Response:Codable>(endpoint:String, request:Request) throws -> Response {
        var req = URLRequest(url:URL(string:"https://api.dropboxapi.com/2/\(endpoint)")!)
        req.httpMethod = "POST"
        req.allHTTPHeaderFields = ["Authorization": "Bearer \(self.token)", "Content-Type": "application/json"]
        req.httpBody = try JSONEncoder().encode(request)
        
        let response:APIResponse<Response> = try req.executeAPIRequest()
        return response.value
    }
    
    func download(_ srcURL:URL) throws -> Data {
        let sema = DispatchSemaphore(value:0);
        let session = URLSession.shared;
        var result:Data? = nil
        var outerError:Error? = nil
        
        session.dataTask(with: srcURL) { (data, response, httpError) in
            outerError = httpError
            if ((response as? HTTPURLResponse)?.statusCode == 200) {
                result = data
            }
            sema.signal()
        }.resume()
        
        sema.wait()
        
        if (result == nil) {
            let reason = outerError?.localizedDescription ?? ""
            throw NSError.init(domain: "migrator", code: 0, userInfo: [NSLocalizedDescriptionKey:"Cannot download \(srcURL): \(reason)"])
        }
        
        return result!
    }
    
    struct ListSharedLinksRequest : Codable {
        let path:String
        let direct_only:Bool
    }
    
    struct ListSharedLinksResponse : Codable {
        struct Link : Codable {
            let url:String
        }
        let links:[Link]
    }
    
    struct ShareLinkRequest : Codable {
        let path:String
        struct Settings : Codable {
            let requested_visibility:String
        }
        let settings:Settings
    }
    
    struct ShareLinkResponse : Codable {
        let url:String
    }
    
    func share(_ path:String) throws -> String {
        let sharedAlready:ListSharedLinksResponse = try api(endpoint: "sharing/list_shared_links", request:ListSharedLinksRequest(path:path, direct_only:true))
        if (sharedAlready.links.count > 0) {
            return sharedAlready.links.first!.url
        }
        
        let response:ShareLinkResponse = try api(endpoint: "sharing/create_shared_link_with_settings", request: ShareLinkRequest(path:path, settings:ShareLinkRequest.Settings(requested_visibility:"public")))
        return response.url
    }
    
    override func migrate(url:String) throws -> String {
        let srcURL = URL(string: url)
        if (srcURL == nil) {
            throw NSError.init(domain: "migrator", code: 0, userInfo: [NSLocalizedDescriptionKey: "\(url) is not a valid URL"])
        }
        
        let contents = try download(srcURL!)
        let uploadResponse = try upload(data: contents, args: UploadRequest(path: srcURL!.path, mode: "add", autorename: true))
        var shareURLStr = try share(uploadResponse.id)
        if (shareURLStr.hasSuffix(".mov?dl=0")) {
            let start = shareURLStr.index(shareURLStr.endIndex, offsetBy: -("?dl=0".count))
            let end = shareURLStr.endIndex
            shareURLStr.replaceSubrange(start..<end, with: "?dl=1")
        } else if (shareURLStr.hasSuffix("?dl=0")) {
            let start = shareURLStr.index(shareURLStr.endIndex, offsetBy: -("?dl=0".count))
            let end = shareURLStr.endIndex
            shareURLStr.replaceSubrange(start..<end, with: "?raw=1")
        }
        
        return shareURLStr
    }
}

// ********************************************************************************
// Main
//

func usage() {
    print("""
        Usage: attachment-migrator/main.swift -github-token <token> [-dropbox-token <token>] [-transfer-script '<command>']
        
        Guide to Arguments:
        
        \t-github-token: A GitHub personal access token created at https://github.com/settings/tokens, with repo scope.
        \t-dropbox-token: A Dropbox OAuth token, created at https://www.dropbox.com/developers/apps/create.
        \t-transfer-script: A command, to be executed with /bin/bash, that takes as its last argument the URL of an attachment to be migrated, and which prints out the migrated URL to stdout on success. Either -dropbox-token or -transfer-script must be specified.
        \t-dry-run: YES or NO. If YES, just print GitHub URLs of issues and comments that need to be migrated, but don't actually modify anything. If NO, actually update the issues and comments on github.com. Default NO.
        \t-everyone: YES or NO. If YES, attempt to migrate all issues/PRs/comments with shipusercontent.com attachments, regardless of their authors -- this may not succeed if you do not have permission to edit other author's issues/comments. If NO, will only attempt to edit issues/comments which you have authored. Default NO.
        """)
}

// Parse and Validate Command Line Arguments
let githubToken = UserDefaults.standard.string(forKey: "github-token")
let dropboxToken = UserDefaults.standard.string(forKey: "dropbox-token")
let transferScript = UserDefaults.standard.string(forKey: "transfer-script")
let dryRun = UserDefaults.standard.bool(forKey: "dry-run")
let everyone = UserDefaults.standard.bool(forKey: "everyone")

if githubToken == nil || (dropboxToken == nil && transferScript == nil) {
    usage()
    exit(1)
}

// Initialize and Validate GitHub API access
let github = GitHubAPI(githubToken!)
let user:GitHubAPI.User
do {
    user = try github.user()
    if (user.oauthScopes == nil || !user.oauthScopes!.contains("repo")) {
        print("GitHub Token does not contain 'repo' scope. Use a different token.")
        exit(1)
    }
    print("Authenticated GitHub login \"\(user.login)\"")
} catch {
    print("Unable to authenticate with GitHub: \(error)")
    exit(2)
}

// Locate ship.db
let path = NSString(string: "~/Library/RealArtists/Ship2/LocalStore/hub.realartists.com/\(user.id)/ship.db").expandingTildeInPath

let db:ShipDB
do {
    db = try ShipDB(path:path)
} catch {
    print("Unable to open local ship.db: \(error)")
    exit(3)
}

// Discover issue / PRs with bodies that need to be migrated
let author = everyone ? nil : user.login
let issues = db.issuesToBeMigrated(authoredBy: author)

// Discover issue comments that need to be migrated
let issueComments = db.issueCommentsToBeMigrated(authoredBy: author)
let reviewComments = db.reviewCommentsToBeMigrated(authoredBy: author)

let allMigratable:[Migratable] = issues as [Migratable] + issueComments as [Migratable] + reviewComments as [Migratable]

print("*** Will migrate \(allMigratable.count) items\n")

// Migrate (or just iterate and print if dryRun)
let migrator = dropboxToken != nil ? DropboxMigrator(token:dropboxToken!) : ShellMigrator(shell:transferScript!)
var success = 0
var failure = 0
for migratable in allMigratable {
    print("\(migratable.url())")
    if (!dryRun) {
        do {
            let (newBody, urls) = try migrator.migrate(body: migratable.body)
            try github.patch(endpoint: migratable.patchEndpoint(), body: newBody)
            
            for (src, dst) in urls {
                print("\t\(src) => \(dst)")
            }
            success += 1
        } catch {
            print("Migration failed: \(error)")
            failure += 1
        }
    }
    break
}

print("\n\n*** Migrated \(success) item(s) with \(failure) failure(s).")
