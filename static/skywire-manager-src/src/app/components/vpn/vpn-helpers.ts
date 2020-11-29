import { MatDialog, MatDialogRef } from '@angular/material/dialog';
import { Router } from '@angular/router';

import { TabButtonData } from '../layout/top-bar/top-bar.component';
import { VpnClientService, CheckPkResults } from 'src/app/services/vpn-client.service';
import { SnackbarService } from 'src/app/services/snackbar.service';
import GeneralUtils from 'src/app/utils/generalUtils';

export class VpnHelpers {
  private static currentPk = '';

  static changeCurrentPk(pk: string): void {
    this.currentPk = pk;
  }

  /**
   * Data for configuring the tab-bar shown in the header of the vpn client pages.
   */
  static get vpnTabsData(): TabButtonData[] {
    return [
      {
        icon: 'power_settings_new',
        label: 'vpn.start',
        linkParts: ['/vpn', this.currentPk, 'status'],
      },
      {
        icon: 'list',
        label: 'vpn.servers',
        linkParts: ['/vpn', this.currentPk, 'servers'],
      },
      {
        icon: 'flag',
        label: 'vpn.countries',
        linkParts: ['/vpn', this.currentPk, 'status'],
      },
      {
        icon: 'settings',
        label: 'vpn.settings',
        linkParts: ['/vpn', this.currentPk, 'status'],
      },
    ];
  }

  /**
   * Gets the name of the translatable var that must be used for showing a latency value. This
   * allows to add the correct measure suffix.
   */
  static getLatencyValueString(latency: number): string {
    if (latency < 1000) {
      return 'time-in-ms';
    }

    return 'time-in-segs';
  }

  /**
   * Gets the string value to show in the UI a latency value with an adecuate number of decimals.
   * This function converts the value from ms to segs, if appropriate, so the value must be shown
   * using the var returned by getLatencyValueString.
   */
  static getPrintableLatency(latency: number): string {
    if (latency < 1000) {
      return latency + '';
    }

    return (latency / 1000).toFixed(1);
  }

  static processServerChange(
    router: Router,
    vpnClientService: VpnClientService,
    snackbarService: SnackbarService,
    dialog: MatDialog,
    dialogRef: MatDialogRef<any>,
    localPk: string,
    pk: string,
    password: string
  ) {
    const result = vpnClientService.checkNewPk(pk);

    if (result === CheckPkResults.Busy) {
      snackbarService.showError('vpn.server-change.busy-error');

      return;
    }

    if (result === CheckPkResults.SamePkRunning) {
      snackbarService.showWarning('vpn.server-change.already-selected-warning');

      return;
    }

    if (result === CheckPkResults.MustStop) {
      const confirmationDialog =
        GeneralUtils.createConfirmationDialog(dialog, 'vpn.server-change.change-server-while-connected-confirmation');

        confirmationDialog.componentInstance.operationAccepted.subscribe(() => {
          confirmationDialog.componentInstance.closeModal();

          vpnClientService.changeServer(pk, password);
          VpnHelpers.redirectAfterServerChange(router, dialogRef, localPk);
        });

        return;
    }

    if (result === CheckPkResults.SamePkStopped) {
      const confirmationDialog =
        GeneralUtils.createConfirmationDialog(dialog, 'vpn.server-change.start-same-server-confirmation');

        confirmationDialog.componentInstance.operationAccepted.subscribe(() => {
          confirmationDialog.componentInstance.closeModal();

          vpnClientService.start();
          VpnHelpers.redirectAfterServerChange(router, dialogRef, localPk);
        });

        return;
    }

    vpnClientService.changeServer(pk, password);
    VpnHelpers.redirectAfterServerChange(router, dialogRef, localPk);
  }

  private static redirectAfterServerChange(
    router: Router,
    dialogRef: MatDialogRef<any>,
    localPk: string,
  ) {
    if (dialogRef) {
      dialogRef.close();
    }

    router.navigate(['vpn', localPk, 'status']);
  }
}
