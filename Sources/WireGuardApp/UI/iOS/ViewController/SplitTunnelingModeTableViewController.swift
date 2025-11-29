// SPDX-License-Identifier: MIT
// Copyright © 2024 WireGuard LLC. All Rights Reserved.

import UIKit

protocol SplitTunnelingModeTableViewControllerDelegate: AnyObject {
    func splitTunnelingModeSelected(_ mode: SplitTunnelingMode)
}

class SplitTunnelingModeTableViewController: UITableViewController {
    weak var delegate: SplitTunnelingModeTableViewControllerDelegate?
    private let selectedMode: SplitTunnelingMode

    init(selectedMode: SplitTunnelingMode) {
        self.selectedMode = selectedMode
        super.init(style: .grouped)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = tr("splitTunnelingMode")
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "Cell")
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return 3
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "Cell", for: indexPath)

        let mode: SplitTunnelingMode
        let title: String
        let description: String

        switch indexPath.row {
        case 0:
            mode = .allSites
            title = tr("splitTunnelingModeAllSites")
            description = tr("splitTunnelingModeAllSitesDescription")
        case 1:
            mode = .onlyForwardSites
            title = tr("splitTunnelingModeOnlyForwardSites")
            description = tr("splitTunnelingModeOnlyForwardSitesDescription")
        case 2:
            mode = .allExceptSites
            title = tr("splitTunnelingModeAllExceptSites")
            description = tr("splitTunnelingModeAllExceptSitesDescription")
        default:
            fatalError()
        }

        cell.textLabel?.text = title
        cell.detailTextLabel?.text = description
        cell.accessoryType = (mode == selectedMode) ? .checkmark : .none

        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)

        let mode: SplitTunnelingMode
        switch indexPath.row {
        case 0:
            mode = .allSites
        case 1:
            mode = .onlyForwardSites
        case 2:
            mode = .allExceptSites
        default:
            return
        }

        delegate?.splitTunnelingModeSelected(mode)
        navigationController?.popViewController(animated: true)
    }
}

