import ArgumentParser
import Foundation
import PostgresClientKit

struct Encode: ParsableCommand {
    @Option(name: .long, help: "The url of the airsniffer without /?json. Defaults to http://airsniffer.local")
    var url = "http://airsniffer.local"
    
    @Option(name: .shortAndLong, help: "The hostname or IP address of the Postgres server. Defaults to localhost.")
    var host = "localhost"
    
    @Option(name: .long, help: "The port number of the Postgres server. Defaults to 5432.")
    var port = 5432
    
    @Flag(name: .shortAndLong, help: "Whether to use SSL/TLS to connect to the Postgres server. Defaults to false.")
    var ssl = false
    
    @Option(name: .shortAndLong, help: "The Postgres database. Defaults to airsniffer.")
    var database = "airsniffer"
    
    @Option(name: .shortAndLong, help: "The Postgres username. Defaults to airsniffer.")
    var username = "airsniffer"
    
    @Option(name: .shortAndLong, help: "The Postgres password. Defaults to password.")
    var password = "password"
    
    func run() throws {
        let sema = DispatchSemaphore(value: 0)
        
        print("Running swift-airsniffer")
        
        let task = URLSession.shared.dataTask(with: URL(string: "\(url)/?json")!) { data, response, error in
            if let error = error {
                print(error.localizedDescription)
                DispatchSemaphore(value: 1).signal()
                return
            }
            
            guard let data = data else {
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
                    print("No ID returned from entry INSERT...")
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
                print(error.localizedDescription)
                DispatchSemaphore(value: 1).signal()
                return
            }
            
            sema.signal()
        }
        
        task.resume()
        
        sema.wait()
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

Encode.main()
