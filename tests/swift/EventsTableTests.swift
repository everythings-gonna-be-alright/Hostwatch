import Foundation
import Testing
@testable import Hostwatch

@Suite struct EventsTableUpdates {
    let ids = (0..<8).map { _ in UUID() }

    @Test func aBatchPrependsAndTrims() {
        let old = Array(ids[2..<6])                       // rows 2,3,4,5 shown
        let new = Array(ids[0..<5])                       // 0,1 arrived; 5 fell off the end
        let edit = EventsTable.Coordinator.prependAndTrim(from: old, to: new)
        #expect(edit?.inserted == 2)
        #expect(edit?.removed == IndexSet(integer: 3))    // old position of row 5
    }

    @Test func nothingDroppedWhenTheListIsntFull() {
        let old = Array(ids[2..<4]), new = Array(ids[0..<4])
        let edit = EventsTable.Coordinator.prependAndTrim(from: old, to: new)
        #expect(edit?.inserted == 2 && edit?.removed.isEmpty == true)
    }

    @Test func aFilterChangeOrAnEmptyListIsNotIncremental() {
        let old = Array(ids[0..<4])
        #expect(EventsTable.Coordinator.prependAndTrim(from: old, to: [ids[0], ids[2], ids[3]]) == nil)
        #expect(EventsTable.Coordinator.prependAndTrim(from: [], to: old) == nil)
        #expect(EventsTable.Coordinator.prependAndTrim(from: old, to: []) == nil)
    }

    @Test func aReversedListStillComesOutRight() {
        // Three rows in front, the last three gone: what the outline is told is true, if not the shortest way.
        let old = Array(ids[0..<4])
        let edit = EventsTable.Coordinator.prependAndTrim(from: old, to: old.reversed())
        #expect(edit?.inserted == 3 && edit?.removed == IndexSet(integersIn: 1..<4))
    }
}
