import ArgumentParser
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import PostgresClientKit

struct Airsniffer: ParsableCommand {
    static var configuration = CommandConfiguration(
            abstract: "A utility for performing actions with data provided by the AirSniffer.",
            subcommands: [Lametric.self, Store.self],
            defaultSubcommand: Store.self
    )
}

extension Airsniffer {
    struct Store: ParsableCommand {
        @Argument(help: "The url of the airsniffer without /?json.")
        var url = "http://airsniffer.local"
        
        @Option(name: .long, help: "The hostname or IP address of the Postgres server.")
        var host = "localhost"
        
        @Option(name: .long, help: "The port number of the Postgres server.")
        var port = 5432
        
        @Flag(name: .shortAndLong, help: "Whether to use SSL/TLS to connect to the Postgres server.")
        var ssl = false
        
        @Option(name: .shortAndLong, help: "The Postgres database.")
        var database = "airsniffer"
        
        @Option(name: .shortAndLong, help: "The Postgres username.")
        var username = "airsniffer"
        
        @Option(name: .shortAndLong, help: "The Postgres password.")
        var password = "password"
        
        func run() throws {
            let sema = DispatchSemaphore(value: 0)
            
            let task = URLSession.shared.dataTask(with: URL(string: "\(url)/?json")!) { data, response, error in
                if let error = error {
                    print("🛑 \(error.localizedDescription)")
                    DispatchSemaphore(value: 1).signal()
                    return
                }
                
                guard let data = data else {
                    print("🛑 No data received from AirSniffer (\(url)/?json)...")
                    DispatchSemaphore(value: 1).signal()
                    return
                }
                
                do {
                    let airsnifferData = try JSONDecoder().decode(AirsnifferData.self, from: data)
                    
                    let connection = try connectToDB(host, port, ssl, database, username, password)
                    defer { connection.close() }
                    let entryStatement = try connection.prepareStatement(text: "INSERT INTO aq_entry (seconds_since_last_reset, firmware) VALUES ($1, $2) RETURNING id;")
                    defer { entryStatement.close() }
                    let entryCursor = try entryStatement.execute(parameterValues: [Int(airsnifferData.systeminfo.secondsSinceLastReset), airsnifferData.systeminfo.firmware])
                    defer { entryCursor.close() }
                    
                    guard let entryId = try entryCursor.first(where: { _ in true })?.get().columns[0].int() else {
                        print("🛑 No ID returned from entry INSERT...")
                        DispatchSemaphore(value: 1).signal()
                        return
                    }
                    
                    try airsnifferData.values.forEach { value in
                        if value.id != "1" {
                            let valueStatement = try connection.prepareStatement(text: "INSERT INTO aq_entry_value (entry_id, value_id, value) VALUES ($1, $2, $3);")
                            let valueCursor = try valueStatement.execute(parameterValues: [entryId, Int(value.id), value.value])
                            valueStatement.close()
                            valueCursor.close()
                        }
                    }
                } catch {
                    print("🛑 \(error.localizedDescription)")
                    DispatchSemaphore(value: 1).signal()
                    return
                }
                
                print("✅ Successfully inserted data into database!")
                
                sema.signal()
            }
            
            task.resume()
            
            sema.wait()
        }
    }
}

extension Airsniffer {
    struct Lametric: ParsableCommand {
        @Argument(help: "The url of the airsniffer without /?json.")
        var url = "http://airsniffer.local"
        
        @Argument(help: "The push-url of the Lametric Time")
        var lametric = "https://<ip-address>:4343/api/v1/dev/widget/update/com.lametric.bad002a8174dea4fbce93630df3e9afb/1"
        
        @Option(name: .shortAndLong, help: "The Access Token to authenticate against the Lametric Time")
        var accessToken = ""
        
        func run() throws {
            let lametricURL = URL(string: lametric)!
            let green = 3307
            let yellow = 3273
            let red = 3305
            
            let sema = DispatchSemaphore(value: 0)
            
            let task = URLSession.shared.dataTask(with: URL(string: "\(url)/?json")!) { data, response, error in
                if let error = error {
                    print("🛑 \(error.localizedDescription)")
                    DispatchSemaphore(value: 1).signal()
                    return
                }
                
                guard let data = data else {
                    print("🛑 No data received from AirSniffer (\(url)/?json)...")
                    DispatchSemaphore(value: 1).signal()
                    return
                }
                
                do {
                    let airsnifferData = try JSONDecoder().decode(AirsnifferData.self, from: data)
                    
                    guard let grade = airsnifferData.values.first(where: { $0.id == "21" }) else {
                        print("🛑 Couldn't get a valid grade")
                        DispatchSemaphore(value: 1).signal()
                        return
                    }
                    
                    guard let writtenGrade = airsnifferData.values.first(where: { $0.id == "22" }) else {
                        print("🛑 Couldn't get a valid grade")
                        DispatchSemaphore(value: 1).signal()
                        return
                    }
                    
                    guard let gradeValue = Int(grade.value) else {
                        print("🛑 Couldn't get a valid grade")
                        DispatchSemaphore(value: 1).signal()
                        return
                    }
                    
                    var icon: Int
                    
                    if (1...2).contains(gradeValue) {
                        icon = green
                    } else if (3...4).contains(gradeValue) {
                        icon = yellow
                    } else {
                        icon = red
                    }

                    do {
                        try shellOut(to: "curl -k -X POST -H \"Accept: application/json\" -H \"X-Access-Token: \(accessToken)\" -H \"Cache-Control: no-cache\" -d '{\"frames\": [{\"text\": \"\(writtenGrade.value.replacingOccurrences(of: "_", with: " "))\",\"icon\": \(icon),\"index\": 0}]}' \(lametricURL)")
                    } catch {
                        let error = error as! ShellOutError
                        print("🛑 \(error.message)")
                        DispatchSemaphore(value: 1).signal()
                        return
                    }
                    
                    print("✅ Successfully sent data to Lametric Time!")
                    sema.signal()
                } catch {
                    print("🛑 \(error.localizedDescription)")
                    DispatchSemaphore(value: 1).signal()
                    return
                }
            }
            
            task.resume()
            
            sema.wait()
        }
    }
}
    
func connectToDB(_ host: String, _ port: Int, _ ssl: Bool, _ database: String, _ username: String, _ password: String) throws -> Connection {
    var configuration = ConnectionConfiguration()
    configuration.host = host
    configuration.port = port
    configuration.ssl = ssl
    configuration.database = database
    configuration.user = username
    configuration.credential = .scramSHA256(password: password)
    return try Connection(configuration: configuration)
}

struct AirsnifferData: Codable {
    let moduleType: String
    let values: [AirsnifferValue]
    let systeminfo: AirsnifferSysteminfo
    
    enum CodingKeys: String, CodingKey {
        case moduleType = "modultyp"
        case values = "vars"
        case systeminfo = "Systeminfo"
    }
}

struct AirsnifferValue: Codable {
    let id: String
    let homematicName: String
    let description: String
    let unit: String
    let value: String
    
    enum CodingKeys: String, CodingKey {
        case id = "name"
        case homematicName = "homematic_name"
        case description = "desc"
        case unit
        case value
    }
}

struct AirsnifferSysteminfo: Codable {
    let macAddress: String
    let homematicCCUIP: String
    let WLANSSID: String
    let WLANSignalDBM: String
    let secondsSinceLastReset: String
    let firmware: String
    
    enum CodingKeys: String, CodingKey {
        case macAddress = "MAC-Adresse"
        case homematicCCUIP = "Homematic_CCU_ip"
        case WLANSSID = "WLAN_ssid"
        case WLANSignalDBM = "WLAN_Signal_dBm"
        case secondsSinceLastReset = "sec_seit_reset"
        case firmware
    }
}

Airsniffer.main()
