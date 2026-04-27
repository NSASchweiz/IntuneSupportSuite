using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace DapIntuneSupportSuite.Services;

public static class WindowLocalizationHelper
{
    private static readonly ConditionalWeakTable<object, Dictionary<string, string>> OriginalValues = new();

    public static void Attach(Window window)
    {
        window.Loaded += (_, _) => Apply(window);

        EventHandler handler = (_, _) =>
        {
            if (!window.Dispatcher.HasShutdownStarted)
            {
                window.Dispatcher.BeginInvoke(new Action(() => Apply(window)));
            }
        };

        LanguageManager.Instance.LanguageChanged += handler;
        window.Closed += (_, _) => LanguageManager.Instance.LanguageChanged -= handler;
    }

    public static void Apply(Window window)
    {
        if (window is null)
        {
            return;
        }

        if (!BindingOperations.IsDataBound(window, Window.TitleProperty))
        {
            var originalTitle = GetOriginalValue(window, nameof(Window.Title), window.Title);
            window.Title = LanguageManager.Instance.TranslateText(originalTitle);
        }

        if (window.Content is not null)
        {
            ApplyRecursive(window.Content);
        }
    }

    private static void ApplyRecursive(object? node)
    {
        if (node is null || node is string)
        {
            return;
        }

        ApplyCurrentNode(node);

        if (node is DataGrid dataGrid)
        {
            foreach (var column in dataGrid.Columns)
            {
                ApplyDataGridColumn(column);
            }
        }

        if (node is DependencyObject dependencyObject)
        {
            foreach (var child in LogicalTreeHelper.GetChildren(dependencyObject).OfType<object>())
            {
                ApplyRecursive(child);
            }
        }
    }

    private static void ApplyCurrentNode(object node)
    {
        switch (node)
        {
            case TextBlock textBlock when !BindingOperations.IsDataBound(textBlock, TextBlock.TextProperty):
                var originalText = GetOriginalValue(textBlock, nameof(TextBlock.Text), textBlock.Text);
                textBlock.Text = LanguageManager.Instance.TranslateText(originalText);
                break;

            case MenuItem menuItem when !BindingOperations.IsDataBound(menuItem, HeaderedItemsControl.HeaderProperty) && menuItem.Header is string menuHeader:
                var originalMenuHeader = GetOriginalValue(menuItem, nameof(MenuItem.Header), menuHeader);
                menuItem.Header = LanguageManager.Instance.TranslateText(originalMenuHeader);
                break;

            case TabItem tabItem when !BindingOperations.IsDataBound(tabItem, HeaderedContentControl.HeaderProperty) && tabItem.Header is string tabHeader:
                var originalTabHeader = GetOriginalValue(tabItem, nameof(TabItem.Header), tabHeader);
                tabItem.Header = LanguageManager.Instance.TranslateText(originalTabHeader);
                break;

            case HeaderedContentControl headeredContentControl when !BindingOperations.IsDataBound(headeredContentControl, HeaderedContentControl.HeaderProperty) && headeredContentControl.Header is string header:
                var originalHeader = GetOriginalValue(headeredContentControl, nameof(HeaderedContentControl.Header), header);
                headeredContentControl.Header = LanguageManager.Instance.TranslateText(originalHeader);
                break;

            case ContentControl contentControl when !BindingOperations.IsDataBound(contentControl, ContentControl.ContentProperty) && contentControl.Content is string content:
                var originalContent = GetOriginalValue(contentControl, nameof(ContentControl.Content), content);
                contentControl.Content = LanguageManager.Instance.TranslateText(originalContent);
                break;

            case FrameworkElement frameworkElement:
                var toolTip = ToolTipService.GetToolTip(frameworkElement);
                if (toolTip is string toolTipText)
                {
                    var originalToolTip = GetOriginalValue(frameworkElement, "ToolTip", toolTipText);
                    ToolTipService.SetToolTip(frameworkElement, LanguageManager.Instance.TranslateText(originalToolTip));
                }
                break;
        }
    }

    private static void ApplyDataGridColumn(DataGridColumn column)
    {
        if (column.Header is not string header)
        {
            return;
        }

        var originalHeader = GetOriginalValue(column, nameof(DataGridColumn.Header), header);
        column.Header = LanguageManager.Instance.TranslateText(originalHeader);
    }

    private static string GetOriginalValue(object target, string propertyKey, string? currentValue)
    {
        var originalSet = OriginalValues.GetOrCreateValue(target);
        if (!originalSet.TryGetValue(propertyKey, out var original))
        {
            original = currentValue ?? string.Empty;
            originalSet[propertyKey] = original;
        }

        return original;
    }
}
