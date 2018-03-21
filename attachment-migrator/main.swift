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


/* For interacting with GitHub REST API */
class GitHubAPI {
    let token:String;
    
    init(_ token:String) {
        self.token = token
    }
    
    func urlComponents(_ endpoint:String, _ params:Dictionary<String, String>? = nil) -> URLComponents {
        var comps:URLComponents;
        if endpoint.starts(with: "https://") {
            comps = URLComponents.init(string: endpoint)!
        } else {
            var path = endpoint
            if (!endpoint.starts(with: "/")) {
                path = "/\(endpoint)"
            }
            comps = URLComponents.init()
            comps.scheme = "https"
            comps.host = "api.github.com"
            comps.path = path
        }
        
        if (params != nil) {
            comps.queryItems = params!.flatMap() { (key, value) in URLQueryItem.init(name: key, value: value) }
        }
        
        return comps
    }
    
    func headers() -> Dictionary<String, String> {
        return ["Authorization": "token \(self.token)",
                "User-Agent": "realartists",
                "Accept": "application/json"];
    }
    
    func postHeaders() -> Dictionary<String, String> {
        return self.headers().merging(["Content-Type": "application/json"]) { (_, new) in new }
    }
    
    struct GetResponse<T> {
        var value:T;
        var response:HTTPURLResponse;
        
        init(_ value:T, _ response:HTTPURLResponse) {
            self.value = value;
            self.response = response;
        }
    }
    
    func get<T:Codable>(_ endpoint:String, params:Dictionary<String, String>? = nil, headers:Dictionary<String, String>? = nil) throws -> GetResponse<T> {
        
        var allHeaders = self.headers()
        if (headers != nil) {
            allHeaders = allHeaders.merging(headers!) { (_, new) in new }
        }
        
        let comps = self.urlComponents(endpoint, params)
        
        var request = URLRequest(url: comps.url!)
        request.allHTTPHeaderFields = allHeaders
        
        let sema = DispatchSemaphore(value:0);
        let session = URLSession.shared;
        var outerError:Error? = nil
        var result:T? = nil
        var outerResponse:URLResponse? = nil
        session.dataTask(with: request) { (data, response, innerErr) in
            
            outerResponse = response;
            
            if (innerErr != nil) {
                outerError = innerErr;
            } else if (response != nil && !(200..<400).contains((response as! HTTPURLResponse).statusCode)) {
                outerError = NSError.init(domain: NSURLErrorDomain, code: URLError.Code.init(rawValue: (response as! HTTPURLResponse).statusCode).rawValue, userInfo: nil)
            }
            
            if (outerError == nil) {
                let decoder = JSONDecoder()
                do {
                    result = try decoder.decode(T.self, from:data!);
                } catch {
                    outerError = error;
                }
            }
            
            sema.signal();
        }.resume()
        
        sema.wait();
        
        if (outerError != nil) {
            throw outerError!;
        }
        
        return GetResponse(result!, outerResponse as! HTTPURLResponse)
    }
    
    func _getPaged<T:Codable>(endpoint:String, params:Dictionary<String, String>? = nil, headers:Dictionary<String, String>? = nil) throws -> [GetResponse<T>] {
        
        var current = endpoint
        
        var all:[GetResponse<T>] = []
        while (true) {
            let result:GetResponse<T> = try self.get(endpoint, params:params, headers:headers)
            all.append(result)
            
            var next = ""
            if let link:String = (result.response.allHeaderFields["Link"] as? String) {
                let parts = link.components(separatedBy: ", ")
                next = parts.first ?? current
            } else {
                next = current
            }
            
            if (next == current) {
                break
            } else {
                current = next
            }
        }
        
        return all
    }
    
    func getPaged<T:Codable>(endpoint:String, params:Dictionary<String, String>? = nil, headers:Dictionary<String, String>? = nil) throws -> [T] {
        let pages:[GetResponse<T>] = try self._getPaged(endpoint:endpoint, params:params, headers:headers)
        return pages.flatMap() { $0.value }
    }
    
    struct WindowedResult<T:Codable> : Codable {
        var items:[T]
    }
    
    func getWindowPaged<T:Codable>(endpoint:String, params:Dictionary<String, String>? = nil, headers:Dictionary<String, String>? = nil) throws -> [T] {
        let windows:[GetResponse<WindowedResult<T>>] = try self._getPaged(endpoint:endpoint, params:params, headers:headers)
        return windows.flatMap() { $0.value.items }
    }
    
    struct User : Codable {
        var id:Int
        var login:String
        var oauthScopes:[String]?
    }
    
    func user() throws -> User {
        var resp:GetResponse<User> = try self.get("/user")
        let scopes = (resp.response.allHeaderFields["X-OAuth-Scopes"] as? String)?.components(separatedBy: ", ")
        resp.value.oauthScopes = scopes
        return resp.value
    }
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
    
    struct Issue {
        let id:Int
        let number:Int
        let body:String
        let user:GitHubAPI.User
        let repoFullName:String
        
        func url() -> URL {
            return URL(string: "https://github.com/\(repoFullName)/issues/\(number)")!
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
       ZLOCALISSUE.ZBODY,
       ZLOCALISSUE.ZNUMBER,
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
    
    struct Comment {
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
                return URL(string: "https://github.com/\(repoFullName)/pull/\(issueNumber)#discussion-r\(id)")!
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
    
    func migrate(body:String) throws -> String {
        let re = try NSRegularExpression(pattern: "https://shipusercontent.com/[a-f0-9]{32}/[^\\s'\"\\)]+", options: NSRegularExpression.Options(rawValue:0))
        let matches = re.matches(in: body, options: NSRegularExpression.MatchingOptions(rawValue:0), range:NSRangeFromString(body))
        
        var migrated = String(body)
        try matches.reversed().forEach { (match) in
            let bodyRange = Range(match.range(at: 0), in:body)!
            let src = String(body[bodyRange])
            let dst = try migrate(url:src)
            
            migrated.replaceSubrange(bodyRange, with: dst)
        }
        
        return migrated
    }
}
    
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
        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = outputPipe
        try task.run()
        let output = outputPipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        let outputStr = String(data:output, encoding:.utf8) ?? ""
        
        if (task.terminationStatus != 0) {
            throw NSError.init(domain: "shell", code: Int(task.terminationStatus), userInfo: [NSLocalizedDescriptionKey: outputStr])
        }
        
        let dst = outputStr.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        
        try validateMigration(src:url, dst:dst)
        
        return dst
    }
}

class DropboxMigrator : AttachmentMigrator {
    let token:String
    
    init(token:String) {
        self.token = token
    }
    
    func execute<Response:Codable>(_ req:URLRequest) throws -> Response {
        let sema = DispatchSemaphore(value:0);
        let session = URLSession.shared;
        var outerError:Error? = nil
        var result:Response? = nil
        
        session.dataTask(with: req) { (data, response, httpError) in
            let statusCode = response != nil ? (response as! HTTPURLResponse).statusCode : 0
            if (httpError != nil) {
                outerError = httpError
            } else if (statusCode < 200 || statusCode >= 400) {
                let msg = "\(req.url!): HTTP error \(statusCode)" + (data != nil ? (" " + String(data:data!, encoding:.utf8)!) : "")
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
        
        return result!
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
        var req = URLRequest(url:URL(string:"https://api.dropboxapi.com/2/files/upload")!)
        req.httpMethod = "POST"
        let argStr = try String(data:JSONEncoder().encode(args), encoding:.utf8)!
        req.allHTTPHeaderFields = ["Authorization": "Bearer \(self.token)", "Content-Type": "application/octet-stream", "Dropbox-API-Arg": argStr]
        req.httpBody = data
        
        let response:UploadResponse = try execute(req)
        
        return response
    }
    
    func api<Request:Codable, Response:Codable>(endpoint:String, request:Request) throws -> Response {
        var req = URLRequest(url:URL(string:"https://api.dropboxapi.com/2/\(endpoint)")!)
        req.httpMethod = "POST"
        req.allHTTPHeaderFields = ["Authorization": "Bearer \(self.token)", "Content-Type": "application/json"]
        req.httpBody = try JSONEncoder().encode(request)
        
        let response:Response = try execute(req)
        return response
    }
    
    func download(_ srcURL:URL) throws -> Data {
        let sema = DispatchSemaphore(value:0);
        let session = URLSession.shared;
        var result:Data? = nil
        
        session.dataTask(with: srcURL) { (data, response, httpError) in
            if ((response as? HTTPURLResponse)?.statusCode == 200) {
                result = data
            }
            sema.signal()
        }.resume()
        
        sema.wait()
        
        if (result != nil) {
            throw NSError.init(domain: "migrator", code: 0, userInfo: [NSLocalizedDescriptionKey:"Cannot download \(srcURL)"])
        }
        
        return result!
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
        let shareURLStr = try share(uploadResponse.path_display)
        
        return shareURLStr
    }
}

// ********************************************************************************
// Main
//

func usage() {
    let name = ProcessInfo.processInfo.arguments.first ?? "attachment-migrator/main.swift"
    print("""
        Usage: swift \(name) -github-token <token> [-dropbox-token <token>] [-transfer-script '<command>']
        
        Guide to Arguments:
        
        \t-github-token: A GitHub personal access token created at https://github.com/settings/tokens, with repo scope.
        \t-dropbox-token: A Dropbox OAuth token, created at https://www.dropbox.com/developers/apps/create.
        \t-transfer-script: A command, to be executed with the default shell, that takes as its last argument the URL of an attachment to be migrated, and which prints out the migrated URL to stdout on success. Either -dropbox-token or -transfer-script must be specified.
        \t-dry-run: YES or NO. Just print GitHub URLs of issues and comments that need to be migrated, but don't actually modify anything. Default NO.
        \t-everyone: YES or NO. Attempt to migrate all issues/PRs/comments with shipusercontent.com attachments, regardless of their authors. Default NO.
        """)
}

print("Args: \(ProcessInfo.processInfo.arguments)")

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
let api = GitHubAPI(githubToken!)
let user:GitHubAPI.User
do {
    user = try api.user()
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
print("Discovered issues \(issues)")

// Discover issue comments that need to be migrated
let issueComments = db.issueCommentsToBeMigrated(authoredBy: author)
let reviewComments = db.reviewCommentsToBeMigrated(authoredBy: author)

// Migrate (or just iterate and print if dryRun)
let migrator = dropboxToken != nil ? DropboxMigrator(token:dropboxToken!) : ShellMigrator(shell:transferScript!)
for issue in issues {
    print("\(issue.url())")
    if (!dryRun) {
        do {
            let newBody = try migrator.migrate(body: issue.body)
        } catch {
            print("Migration failed: \(error)")
        }
    }
}
