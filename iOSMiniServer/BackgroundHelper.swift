import Foundation
import AVFoundation

/// A helper class to play a silent audio loop in the background to prevent iOS from suspending the app.
class BackgroundHelper {
    static let shared = BackgroundHelper()
    
    private var audioPlayer: AVAudioPlayer?
    private var isPlaying = false
    
    private init() {}
    
    /// Configures the audio session and starts playing the silent audio loop.
    func start() {
        guard !isPlaying else { return }
        
        do {
            let session = AVAudioSession.sharedInstance()
            // Set playback category and enable mixing with other apps
            try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
            try session.setActive(true)
            
            // Generate silent WAV in memory (avoids physical assets)
            let silentData = BackgroundHelper.generateSilentWavData()
            
            audioPlayer = try AVAudioPlayer(data: silentData)
            audioPlayer?.numberOfLoops = -1 // Loop infinitely
            audioPlayer?.volume = 0.01 // Almost zero volume
            audioPlayer?.prepareToPlay()
            audioPlayer?.play()
            
            isPlaying = true
            print("Background silent audio loop started successfully.")
        } catch {
            print("Failed to initialize background audio player: \(error.localizedDescription)")
        }
    }
    
    /// Stops the silent audio loop and deactivates the audio session.
    func stop() {
        guard isPlaying else { return }
        audioPlayer?.stop()
        audioPlayer = nil
        
        do {
            try AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        } catch {
            print("Failed to deactivate audio session: \(error.localizedDescription)")
        }
        
        isPlaying = false
        print("Background silent audio loop stopped.")
    }
    
    // Generates a tiny, 2-second silent mono WAV file in memory (PCM format)
    private static func generateSilentWavData() -> Data {
        let sampleRate: Int32 = 8000
        let numberOfChannels: Int16 = 1
        let bitsPerSample: Int16 = 16
        let durationSeconds: Int = 2
        
        let subchunk2Size = Int32(durationSeconds) * sampleRate * Int32(numberOfChannels) * Int32(bitsPerSample / 8)
        let chunkSize = 36 + subchunk2Size
        
        var header = Data()
        
        // RIFF header
        header.append("RIFF".data(using: .utf8)!)
        var tempChunkSize = chunkSize
        header.append(Data(bytes: &tempChunkSize, count: 4))
        header.append("WAVE".data(using: .utf8)!)
        
        // "fmt " subchunk
        header.append("fmt ".data(using: .utf8)!)
        var subchunk1Size: Int32 = 16
        header.append(Data(bytes: &subchunk1Size, count: 4))
        var audioFormat: Int16 = 1 // PCM
        header.append(Data(bytes: &audioFormat, count: 2))
        var channels = numberOfChannels
        header.append(Data(bytes: &channels, count: 2))
        var rate = sampleRate
        header.append(Data(bytes: &rate, count: 4))
        var byteRate = sampleRate * Int32(numberOfChannels) * Int32(bitsPerSample / 8)
        header.append(Data(bytes: &byteRate, count: 4))
        var blockAlign = numberOfChannels * Int16(bitsPerSample / 8)
        header.append(Data(bytes: &blockAlign, count: 2))
        var bits = bitsPerSample
        header.append(Data(bytes: &bits, count: 2))
        
        // "data" subchunk
        header.append("data".data(using: .utf8)!)
        var tempSubchunk2Size = subchunk2Size
        header.append(Data(bytes: &tempSubchunk2Size, count: 4))
        
        // Silence samples (zeros)
        let silence = Data(repeating: 0, count: Int(subchunk2Size))
        header.append(silence)
        
        return header
    }
}
