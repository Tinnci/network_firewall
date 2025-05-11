#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from typing import Union, Set, List
from PyQt6.QtWidgets import QListWidget

logger = logging.getLogger(__name__)

def update_list_widget_content(list_widget: QListWidget, items: Union[Set[str], List[str]]):
    """
    高效地更新 QListWidget 控件的内容。

    Args:
        list_widget: 要更新的 QListWidget 实例。
        items: 新的项目集合或列表 (字符串)。
    """
    try:
        current_items_text = {list_widget.item(i).text() for i in range(list_widget.count())}
        
        # Ensure new_items_text is a set for efficient comparison
        if isinstance(items, list):
            new_items_text = set(items)
        elif isinstance(items, set):
            new_items_text = items
        else:
            # Handle unexpected type, perhaps log an error or raise
            logger.error(f"Error: Unexpected type for items in update_list_widget_content: {type(items)}")
            return

        items_to_add = new_items_text - current_items_text
        items_to_remove = current_items_text - new_items_text

        # Remove items
        if items_to_remove:
            rows_to_remove = []
            for i in range(list_widget.count()):
                try:
                    if list_widget.item(i).text() in items_to_remove:
                        rows_to_remove.append(i)
                except AttributeError:  # Should not happen if items are always QListWidgetItems
                    pass
            for i in sorted(rows_to_remove, reverse=True):
                list_widget.takeItem(i)
        
        # Add new items
        if items_to_add:
            list_widget.addItems(sorted(list(items_to_add)))
            
    except Exception as e:
        # Log or print error specific to this utility
        logger.error(f"Error updating list widget '{list_widget.objectName()}' via ui_utils: {e}", exc_info=True) 