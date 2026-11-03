/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

document.addEventListener("DOMContentLoaded", () => {
    const tableInfos = Array.from(
        document.querySelectorAll(".pst-scrollable-table-container > table")
    )
        .map((table) => ({
            table,
            wrapper: table.parentElement,
            header: table.tHead,
        }))
        .filter(({ wrapper, header }) => wrapper && header);

    if (!tableInfos.length) {
        return;
    }

    const articleToolbar = document.querySelector(".bd-header-article");
    const floatingContainer = document.createElement("div");
    const floatingTable = document.createElement("table");
    floatingContainer.className = "spsdk-floating-table-header";
    floatingContainer.setAttribute("aria-hidden", "true");
    floatingContainer.hidden = true;
    floatingContainer.append(floatingTable);
    document.body.append(floatingContainer);

    let activeTable = null;
    let updatePending = false;

    const hideFloatingHeader = () => {
        floatingContainer.hidden = true;
        activeTable = null;
    };

    const cloneHeader = (tableInfo) => {
        floatingTable.className = tableInfo.table.className;
        floatingTable.replaceChildren(tableInfo.header.cloneNode(true));
        activeTable = tableInfo.table;
    };

    const updateFloatingHeader = () => {
        updatePending = false;
        const toolbarBottom = articleToolbar
            ? Math.max(0, articleToolbar.getBoundingClientRect().bottom)
            : 0;
        let activeInfo = null;

        for (const tableInfo of tableInfos) {
            const headerRect = tableInfo.header.getBoundingClientRect();
            const tableRect = tableInfo.table.getBoundingClientRect();
            if (
                headerRect.top <= toolbarBottom &&
                tableRect.bottom > toolbarBottom + headerRect.height
            ) {
                activeInfo = { ...tableInfo, headerRect, tableRect };
                break;
            }
        }

        if (!activeInfo) {
            hideFloatingHeader();
            return;
        }

        if (activeTable !== activeInfo.table) {
            cloneHeader(activeInfo);
        }

        const wrapperRect = activeInfo.wrapper.getBoundingClientRect();
        const visibleLeft = Math.max(0, wrapperRect.left);
        const visibleRight = Math.min(window.innerWidth, wrapperRect.right);
        if (visibleRight <= visibleLeft) {
            hideFloatingHeader();
            return;
        }

        const sourceCells = activeInfo.header.querySelectorAll("th, td");
        const clonedCells = floatingTable.tHead.querySelectorAll("th, td");
        sourceCells.forEach((sourceCell, index) => {
            const width = `${sourceCell.getBoundingClientRect().width}px`;
            clonedCells[index].style.width = width;
            clonedCells[index].style.minWidth = width;
            clonedCells[index].style.maxWidth = width;
        });

        floatingContainer.style.top = `${toolbarBottom}px`;
        floatingContainer.style.left = `${visibleLeft}px`;
        floatingContainer.style.width = `${visibleRight - visibleLeft}px`;
        floatingContainer.style.height = `${activeInfo.headerRect.height}px`;
        floatingTable.style.width = `${activeInfo.tableRect.width}px`;
        floatingTable.style.transform = `translateX(${activeInfo.tableRect.left - visibleLeft}px)`;
        floatingContainer.hidden = false;
    };

    const requestUpdate = () => {
        if (!updatePending) {
            updatePending = true;
            window.requestAnimationFrame(updateFloatingHeader);
        }
    };

    window.addEventListener("scroll", requestUpdate, { passive: true });
    window.addEventListener("resize", requestUpdate);
    tableInfos.forEach(({ wrapper }) => {
        wrapper.addEventListener("scroll", requestUpdate, { passive: true });
    });

    const resizeObserver = new ResizeObserver(requestUpdate);
    tableInfos.forEach(({ wrapper }) => resizeObserver.observe(wrapper));
    requestUpdate();
});