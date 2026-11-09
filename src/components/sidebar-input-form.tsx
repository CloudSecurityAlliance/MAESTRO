
"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import React from "react";

import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { USE_CASES } from "@/data/use-cases";
import { Spinner } from "./icons";
import { X } from "lucide-react";
import { CodebaseInput } from "./codebase-input";

const formSchema = z.object({
  architectureDescription: z
    .string()
    .min(50, {
      message: "Architecture description must be at least 50 characters.",
    })
    .max(5000, {
      message: "Description must not be longer than 5000 characters.",
    }),
  preset: z.string().optional(),
});

type SidebarInputFormProps = {
  onAnalyze: (architectureDescription: string) => Promise<void>;
  onStop: () => void;
  isAnalyzing: boolean;
  buttonText: string;
  onDescriptionChange: (description: string) => void;
};

export function SidebarInputForm({
  onAnalyze,
  onStop,
  isAnalyzing,
  buttonText,
  onDescriptionChange,
}: SidebarInputFormProps) {
  const [isPreparingCodebase, setIsPreparingCodebase] = React.useState(false);
  const inputDisabled = isAnalyzing || isPreparingCodebase;
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      architectureDescription: USE_CASES[0].description,
      preset: USE_CASES[0].value,
    },
  });

  const archDescription = form.watch("architectureDescription");
  React.useEffect(() => {
      onDescriptionChange(archDescription);
  }, [archDescription, onDescriptionChange]);


  function onSubmit(values: z.infer<typeof formSchema>) {
    if (inputDisabled) return;
    onAnalyze(values.architectureDescription);
  }

  const handlePresetChange = (value: string) => {
    const selectedUseCase = USE_CASES.find((uc) => uc.value === value);
    if (selectedUseCase) {
      form.setValue("architectureDescription", selectedUseCase.description);
      form.setValue("preset", selectedUseCase.value);
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className="flex flex-col h-full"
      >
        <div className="flex-grow p-4 space-y-4 overflow-y-auto">
          <CodebaseInput
            disabled={isAnalyzing}
            onBusyChange={setIsPreparingCodebase}
            onArchitecture={(description) => {
              form.setValue("architectureDescription", description, { shouldValidate: true, shouldDirty: true });
              form.setValue("preset", "");
            }}
          />
          <FormField
            control={form.control}
            name="preset"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Use-Case Presets</FormLabel>
                <Select
                  onValueChange={handlePresetChange}
                  value={field.value}
                  disabled={inputDisabled}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select a preset use-case" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {USE_CASES.map((useCase) => (
                      <SelectItem key={useCase.value} value={useCase.value}>
                        {useCase.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormDescription>
                  Select a preset to auto-populate the description.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="architectureDescription"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Architecture Description</FormLabel>
                <FormControl>
                  <Textarea
                    placeholder="Describe your system architecture in detail..."
                    className="resize-none h-64"
                    {...field}
                    disabled={inputDisabled}
                  />
                </FormControl>
                <FormDescription>
                  Provide a detailed description for a precise AI threat
                  analysis.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>
        <div className="p-4 border-t bg-sidebar-background">
           {isAnalyzing ? (
              <Button type="button" variant="destructive" className="w-full" onClick={onStop}>
                <X className="mr-2 h-4 w-4" />
                Stop Analysis
              </Button>
            ) : (
              <Button type="submit" className="w-full" disabled={inputDisabled}>
                {isAnalyzing && <Spinner className="mr-2 h-4 w-4" />}
                {buttonText}
              </Button>
            )}
        </div>
      </form>
    </Form>
  );
}
